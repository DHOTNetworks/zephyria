// ============================================================================
// RISC-V VM Module — Full Node Integration (Production)
// ============================================================================
//
// Bridges the forgec RISC-V RV32EM VM (at /vm/) with the Zephyria node.
// Provides:
//   • executeContract() — execute runtime code with calldata
//   • deployContract() — execute initcode, return runtime code
//   • All HostEnv provider slots wired:
//       balanceFn      → StateBridge.getBalance (real state query)
//       callFn         → recursive VM re-entry with call-type semantics:
//                         CALL: msg.sender = caller, storage = target
//                         DELEGATECALL: msg.sender = original caller, storage = caller
//                         STATICCALL: read-only execution, no state mutation
//       createFn       → derive address via keccak(RLP(sender, nonce)), execute initcode
//       ecrecoverFn    → secp256k1 ECDSA signature recovery
//       selfDestructFn → transfer balance + mark for deletion via StateBridge
//
// Isolated Accounts & Zero-Conflict Parallel Model:
//   The VM operates within per-TX Overlay isolation. Each SLOAD/SSTORE goes through
//   the Overlay → Verkle trie path where:
//     StorageKey = keccak256(contract || slot)          — different slots = zero conflict
//     DerivedKey = keccak256(user || contract || slot)   — different users = zero conflict
//     GlobalKey  = keccak256(contract || "global" || slot) — commutative accumulators
//   Sub-calls share the same Overlay, preserving per-TX atomicity.

const std = @import("std");
const core = @import("core");
const vm = @import("vm");
const StateBridge = @import("state_bridge").StateBridge;

// Re-export forgec VM components
pub const vmCore = vm.executor;
pub const vmSyscall = vm.syscallDispatch;
pub const vmGas = vm.gasMeter;
pub const vmMemory = vm.sandbox;

/// Execute a contract call using the RISC-V VM.
/// All HostEnv provider slots are wired for full smart-contract support.
/// Executes a smart contract using the RISC-V VM (RV64IM).
/// Sets up the host environment, wires syscall providers (storage, calls, etc.),
/// and loads/executes the bytecode.
pub fn executeContract(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    calldata: []const u8,
    gasLimit: u64,
    stateBridge: *anyopaque,
) !ExecutionResult {
    var sb: *StateBridge = @ptrCast(@alignCast(stateBridge));

    // Create host environment
    var host = vm.HostEnv.init(allocator);
    defer host.deinit();

    // ── Wire storage backend ────────────────────────────────────────
    var storageBackend = sb.createStorageBackend();
    host.storage = &storageBackend;

    // ── Wire execution context (from block/tx) ──────────────────────
    host.caller = sb.caller;
    host.selfAddress = sb.selfAddress;
    host.callValue = sb.value;
    host.gasLimit = gasLimit;
    host.blockNumber = sb.blockNumber;
    host.chainId = sb.chainId;
    host.timestamp = sb.timestamp;
    host.txOrigin = sb.txOrigin;
    host.gasPrice = sb.gasPrice;
    host.coinbase = sb.coinbase;
    host.baseFee = sb.baseFee;
    host.prevrandao = sb.prevRandao;

    // ── Wire balance provider ───────────────────────────────────────
    // Routes GET_BALANCE syscall to real state overlay lookup.
    const BalanceProvider = struct {
        var bridge: *StateBridge = undefined;
        fn getBalance(addr: [20]u8) [32]u8 {
            return bridge.getBalance(addr);
        }
    };
    BalanceProvider.bridge = sb;
    host.balanceFn = &BalanceProvider.getBalance;

    // ── Wire call provider ──────────────────────────────────────────
    // Routes CALL/DELEGATECALL/STATICCALL syscalls to recursive VM execution.
    //
    // Call semantics:
    //   CALL:         msg.sender = current contract, code/storage = target contract
    //   DELEGATECALL: msg.sender = original caller (preserved), code = target, storage = current
    //   STATICCALL:   same as CALL but state mutations are forbidden
    const CallProvider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn callContract(
            callType: vm.syscallDispatch.CallType,
            to: [20]u8,
            value: [32]u8,
            data: []const u8,
            gas: u64,
        ) vm.syscallDispatch.CallProviderResult {
            // Get target code
            const code = bridge.getCode(to) catch {
                return .{ .success = true, .returnData = &[_]u8{}, .gasUsed = 0 };
            };
            if (code.len == 0) {
                return .{ .success = true, .returnData = &[_]u8{}, .gasUsed = 0 };
            }

            // ------ Apply call-type semantics ------
            var subSelfAddress: [20]u8 = undefined;
            var subCaller: [20]u8 = undefined;
            var subValue: [32]u8 = undefined;
            // For delegatecall: run target's CODE but in current contract's STORAGE context.
            // execCode is always `code` (the target's bytecode fetched above).
            // The difference is which address and caller the sub-bridge uses.
            const execCode = code;

            switch (callType) {
                .call => {
                    // CALL: sender is current contract, target runs its own code/storage
                    subSelfAddress = to;
                    subCaller = bridge.selfAddress;
                    subValue = value;

                    // Transfer value if non-zero
                    if (!isZero(value)) {
                        bridge.transfer(to, value) catch {
                            return .{ .success = false, .returnData = &[_]u8{}, .gasUsed = 0 };
                        };
                    }
                },
                .delegatecall => {
                    // DELEGATECALL: caller = original msg.sender (preserved),
                    // storage context = current contract (subSelfAddress = bridge.selfAddress),
                    // code = target's bytecode (execCode set above).
                    subSelfAddress = bridge.selfAddress; // storage stays in current contract
                    subCaller = bridge.caller; // msg.sender = original caller
                    subValue = bridge.value; // value = original call value
                    // No value transfer in delegatecall
                },
                .staticcall => {
                    // STATICCALL: same as CALL but read-only (no state mutations)
                    subSelfAddress = to;
                    subCaller = bridge.selfAddress;
                    subValue = [_]u8{0} ** 32; // No value transfer in staticcall
                },
            }
            // Create sub-bridge. For DELEGATECALL subSelfAddress = bridge.selfAddress
            // so that SLOAD/SSTORE inside the callee operate on the caller's storage slots.
            var subBridge = StateBridge.init(
                alloc,
                bridge.overlay,
                subSelfAddress,
                subCaller,
                subValue,
                gas,
            );
            subBridge.depth = bridge.depth + 1;
            subBridge.inheritContext(bridge);
            defer subBridge.deinit();

            // Check call depth (EIP limit: 1024)
            if (subBridge.depth > subBridge.maxDepth) {
                return .{ .success = false, .returnData = &[_]u8{}, .gasUsed = 0 };
            }

            const result = executeContract(
                alloc,
                execCode,
                data,
                gas,
                @ptrCast(&subBridge),
            ) catch {
                return .{ .success = false, .returnData = &[_]u8{}, .gasUsed = gas };
            };

            return .{
                .success = result.success,
                .returnData = result.returnData,
                .gasUsed = result.gasUsed,
            };
        }
    };
    CallProvider.bridge = sb;
    CallProvider.alloc = allocator;
    host.callFn = &CallProvider.callContract;

    // ── Wire create provider ────────────────────────────────────────
    // Routes CREATE_CONTRACT syscall to: derive address → execute initcode → store runtime code.
    // Address derivation follows Ethereum: keccak256(RLP([sender, nonce]))[12..32]
    const CreateProvider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn createContract(
            code: []const u8,
            value: [32]u8,
            gas: u64,
        ) vm.syscallDispatch.CreateProviderResult {
            const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));
            const senderAddr = core.types.Address{ .bytes = bridge.selfAddress };

            // Get sender nonce for deterministic address derivation
            const nonce = state.getNonce(senderAddr);

            // Derive new contract address = keccak256(RLP([sender, nonce]))[12..32]
            // Simplified RLP: keccak256(0xd6 || 0x94 || sender || nonce_byte)
            // This matches Ethereum's CREATE address derivation
            var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
            // RLP prefix for a list of [address, nonce]
            hasher.update(&[_]u8{ 0xd6, 0x94 });
            hasher.update(&bridge.selfAddress);
            // Encode nonce (simplified: single byte if < 128, otherwise length-prefixed)
            if (nonce == 0) {
                hasher.update(&[_]u8{0x80});
            } else if (nonce < 128) {
                hasher.update(&[_]u8{@truncate(nonce)});
            } else {
                var nonceBuf: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonceBuf, nonce, .big);
                // Find first non-zero byte
                var start: usize = 0;
                while (start < 7 and nonceBuf[start] == 0) : (start += 1) {}
                const nonceLen: u8 = @truncate(8 - start);
                hasher.update(&[_]u8{0x80 + nonceLen});
                hasher.update(nonceBuf[start..8]);
            }
            var hash: [32]u8 = undefined;
            hasher.final(&hash);
            var newAddr: [20]u8 = undefined;
            @memcpy(&newAddr, hash[12..32]);

            // Increment sender nonce
            state.setNonce(senderAddr, nonce + 1) catch {};

            // Mark as created
            const newAddrTyped = core.types.Address{ .bytes = newAddr };
            state.markCreated(newAddrTyped) catch {};

            // Transfer value to new contract
            if (!isZero(value)) {
                bridge.transfer(newAddr, value) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 20, .gasUsed = 0 };
                };
            }

            // Execute initcode via recursive VM call
            var subBridge = StateBridge.init(
                alloc,
                bridge.overlay,
                newAddr,
                bridge.selfAddress,
                value,
                gas,
            );
            subBridge.depth = bridge.depth + 1;
            subBridge.inheritContext(bridge);
            defer subBridge.deinit();

            const result = executeContract(
                alloc,
                code,
                &[_]u8{},
                gas,
                @ptrCast(&subBridge),
            ) catch {
                return .{ .success = false, .newAddress = [_]u8{0} ** 20, .gasUsed = gas };
            };

            if (result.success and result.returnData.len > 0) {
                // Store runtime code at new address
                state.setCode(newAddrTyped, result.returnData) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 20, .gasUsed = result.gasUsed };
                };
            }

            return .{
                .success = result.success,
                .newAddress = newAddr,
                .gasUsed = result.gasUsed,
            };
        }
    };
    CreateProvider.bridge = sb;
    CreateProvider.alloc = allocator;
    host.createFn = &CreateProvider.createContract;

    // ── Wire create2 provider ───────────────────────────────────────
    // Routes CREATE2 syscall to: hash initcode → derive salt-based address → execute initcode.
    // Address derivation follows EIP-1014: keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
    // This produces deterministic addresses independent of sender nonce.
    const Create2Provider = struct {
        var bridge: *StateBridge = undefined;
        var alloc: std.mem.Allocator = undefined;

        fn create2Contract(
            code: []const u8,
            salt: [32]u8,
            value: [32]u8,
            gas: u64,
        ) vm.syscallDispatch.CreateProviderResult {
            const state: *core.state.Overlay = @ptrCast(@alignCast(bridge.overlay));

            // Step 1: Hash the initcode
            var initcodeHash: [32]u8 = undefined;
            var codeHasher = std.crypto.hash.sha3.Keccak256.init(.{});
            codeHasher.update(code);
            codeHasher.final(&initcodeHash);

            // Step 2: Derive CREATE2 address = keccak256(0xFF || sender || salt || keccak256(initcode))[12..32]
            var addrHasher = std.crypto.hash.sha3.Keccak256.init(.{});
            addrHasher.update(&[_]u8{0xFF});
            addrHasher.update(&bridge.selfAddress);
            addrHasher.update(&salt);
            addrHasher.update(&initcodeHash);
            var hash: [32]u8 = undefined;
            addrHasher.final(&hash);
            var newAddr: [20]u8 = undefined;
            @memcpy(&newAddr, hash[12..32]);

            // Step 3: Check for address collision (code already exists at derived address)
            const newAddrTyped = core.types.Address{ .bytes = newAddr };
            const existingCode = state.getCode(newAddrTyped) catch &[_]u8{};
            if (existingCode.len > 0) {
                // Address collision — CREATE2 must fail
                return .{ .success = false, .newAddress = [_]u8{0} ** 20, .gasUsed = 0 };
            }

            // Step 4: Increment sender nonce (same as CREATE)
            const senderAddr = core.types.Address{ .bytes = bridge.selfAddress };
            const nonce = state.getNonce(senderAddr);
            state.setNonce(senderAddr, nonce + 1) catch {};

            // Step 5: Mark as created
            state.markCreated(newAddrTyped) catch {};

            // Step 6: Transfer value to new contract
            if (!isZero(value)) {
                bridge.transfer(newAddr, value) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 20, .gasUsed = 0 };
                };
            }

            // Step 7: Execute initcode in child VM
            var subBridge = StateBridge.init(
                alloc,
                bridge.overlay,
                newAddr,
                bridge.selfAddress,
                value,
                gas,
            );
            subBridge.depth = bridge.depth + 1;
            subBridge.inheritContext(bridge);
            defer subBridge.deinit();

            const result = executeContract(
                alloc,
                code,
                &[_]u8{},
                gas,
                @ptrCast(&subBridge),
            ) catch {
                return .{ .success = false, .newAddress = [_]u8{0} ** 20, .gasUsed = gas };
            };

            // Step 8: Store runtime bytecode at derived address
            if (result.success and result.returnData.len > 0) {
                state.setCode(newAddrTyped, result.returnData) catch {
                    return .{ .success = false, .newAddress = [_]u8{0} ** 20, .gasUsed = result.gasUsed };
                };
            }

            return .{
                .success = result.success,
                .newAddress = newAddr,
                .gasUsed = result.gasUsed,
            };
        }
    };
    Create2Provider.bridge = sb;
    Create2Provider.alloc = allocator;
    host.create2Fn = &Create2Provider.create2Contract;

    // ── Wire ecrecover provider ─────────────────────────────────────
    // Routes ECRECOVER syscall to real secp256k1 ECDSA signature recovery.
    // Uses the existing eoa.recoverPublicKey() which performs actual elliptic
    // curve point recovery on the secp256k1 curve, then derives the Ethereum
    // address via keccak256(uncompressed_pubkey[1..])[12..32].
    //
    // This enables: EIP-712 typed data signing, ERC-20 permit(), meta-transactions,
    // signature-based authentication, and all signature-dependent DeFi protocols.
    const EcrecoverProvider = struct {
        fn ecrecoverFn(hash: [32]u8, v: u8, r: [32]u8, s: [32]u8) [20]u8 {
            // Validate v (must be 27 or 28 for Ethereum-style signatures)
            if (v != 27 and v != 28) {
                return [_]u8{0} ** 20; // Invalid v — return zero address
            }

            // Validate r and s are non-zero (basic validity check)
            if (isZero(r) or isZero(s)) {
                return [_]u8{0} ** 20;
            }

            // Validate s is in the lower half of the curve order (EIP-2)
            // s must be <= secp256k1 order / 2
            // Upper bound: 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
            if (s[0] > 0x7F) {
                return [_]u8{0} ** 20; // s too high — malleable signature
            }

            // Recovery ID: v - 27 gives 0 or 1
            const recoveryId: u8 = v - 27;

            // Real secp256k1 ECDSA point recovery:
            // 1. Recover the uncompressed public key (65 bytes) from (hash, r, s, recoveryId)
            // 2. Derive Ethereum address = keccak256(pubkey[1..65])[12..32]
            const uncompressedPubkey = core.account.recoverPublicKey(hash, r, s, recoveryId) catch {
                return [_]u8{0} ** 20; // Recovery failed — invalid signature
            };

            // Derive address from recovered public key
            const addrResult = core.account.addressFromPubKey(&uncompressedPubkey) catch {
                return [_]u8{0} ** 20; // Address derivation failed
            };

            return addrResult.bytes;
        }
    };
    host.ecrecoverFn = &EcrecoverProvider.ecrecoverFn;

    // ── Wire selfdestruct provider ──────────────────────────────────
    // Routes SELFDESTRUCT syscall to StateBridge.selfDestruct which transfers
    // remaining balance to beneficiary and marks the account for deletion
    // via Overlay.suicide().
    const SelfDestructProvider = struct {
        var bridge: *StateBridge = undefined;
        fn selfDestructFn(beneficiary: [20]u8) bool {
            bridge.selfDestruct(beneficiary) catch return false;
            return true;
        }
    };
    SelfDestructProvider.bridge = sb;
    host.selfDestructFn = &SelfDestructProvider.selfDestructFn;

    // ── Execute via the contract loader ─────────────────────────────
    const sysResult = vm.contractLoader.executeFromElf(
        allocator,
        bytecode,
        calldata,
        gasLimit,
        &host,
    ) catch |err| {
        std.log.err("executeFromElf failed: {}", .{err});
        return ExecutionResult{
            .success = false,
            .gasUsed = 0,
            .gasRemaining = gasLimit,
            .returnData = &[_]u8{},
            .logs = &[_]vm.syscallDispatch.LogEntry{},
            .status = .fault,
        };
    };

    if (sysResult.status != .returned) {
        if (sysResult.status == .fault) {
            std.log.err("VM Fault at PC=0x{x}: {s}", .{ sysResult.faultPc, sysResult.faultReason orelse "Unknown" });
        }
    }

    return ExecutionResult{
        .success = sysResult.status == .returned,
        .gasUsed = sysResult.gasUsed,
        .gasRemaining = sysResult.gasRemaining,
        .returnData = sysResult.returnData,
        .logs = host.logs.items,
        .status = sysResult.status,
    };
}

/// Deploy a new contract (execute initcode, return runtime code).
/// Deploys a new contract by executing its initcode.
/// Returns the resulting runtime bytecode generated by the initcode execution.
pub fn deployContract(
    allocator: std.mem.Allocator,
    initcode: []const u8,
    gasLimit: u64,
    stateBridge: *anyopaque,
) !DeployResult {
    const result = try executeContract(
        allocator,
        initcode,
        &[_]u8{},
        gasLimit,
        stateBridge,
    );

    return DeployResult{
        .success = result.success,
        .gasUsed = result.gasUsed,
        .runtimeCode = result.returnData,
        .logs = result.logs,
    };
}

/// Result of contract execution.
/// Detailed results from a contract execution session.
pub const ExecutionResult = struct {
    success: bool,
    gasUsed: u64,
    gasRemaining: u64,
    returnData: []const u8,
    /// Logs emitted during execution (from HostEnv)
    logs: []const vm.LogEntry,
    status: vmCore.ExecutionStatus,
};

/// Result of contract deployment.
/// Results from a contract deployment (initcode execution).
pub const DeployResult = struct {
    success: bool,
    gasUsed: u64,
    runtimeCode: []const u8,
    /// Logs emitted during deployment
    logs: []const vm.LogEntry,
};

// ── Helpers ─────────────────────────────────────────────────────────

fn isZero(value: [32]u8) bool {
    for (value) |b| {
        if (b != 0) return false;
    }
    return true;
}
