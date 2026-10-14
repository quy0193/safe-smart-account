# Security review: safe-smart-account (fork quy0193, HEAD f8fc2f2 + review commits)

Ngày review: 2026-10-14. Người thực hiện: Claude (Claude Code), theo yêu cầu của chủ repo.

## 1. Phạm vi và bối cảnh

- Repo là bản fork của `safe-global/safe-smart-account`, package version `1.5.0`, nhánh `main` ở commit `f8fc2f2` ("Fix Revert Data Length in `CompatibilityFallbackHandler.simulate` (#1123)"). Nhánh này KHÔNG trùng với tag release 1.5.0: `README.md` cảnh báo `main` là mã chưa phát hành.
- Toàn bộ 58 contract production dưới `contracts/` (trừ `contracts/test/**`), script deploy và task TypeScript dưới `src/`, cấu hình `hardhat.config.ts`, CI (`.github/workflows/*.yml`), cấu hình Certora, tài liệu `docs/*.md` và `CHANGELOG.md` đều nằm trong phạm vi.
- Threat model dùng để chấm mức độ nghiêm trọng: owner được tin trong phạm vi threshold; module, guard, fallback handler và delegatecall target được tin sau khi owner bật; relayer hoặc bất kỳ ai có thể gọi `execTransaction` với chữ ký hợp lệ; một singleton phục vụ mọi Safe qua proxy; `contracts/examples/*` là mã tham khảo được ship trong npm package nhưng không có script deploy.
- Các commit vào sau audit 1.5.0 (Certora `1c8b24a` 2025-01-23, Ackee `5d26505` 2025-05-27, chuẩn bị release 1.5.0 `45ac9b8` 2025-07-03): `#998` Safe tự làm owner (2025-07-10), `#1062` EIP-7702 self-ownership (2025-12-12), `#1061` chữ ký secp256r1 EIP-7951 (2026-01-14), `#1115` `SecuredSignatureValidator` (2026-06), `#1123` fix `simulate` (2026-09). Đây là vùng mã ít được soi nhất và được ưu tiên.

## 2. Phương pháp

1. Khảo sát inline: đọc `Safe.sol`, các base/common/handler/library/proxy chính, lịch sử git, CHANGELOG, audit notes.
2. Giai đoạn Find: 11 finder độc lập, mỗi finder một góc nhìn và một tập file: `core-sig`, `gas-refund`, `managers`, `proxy-setup-migration`, `handlers`, `libraries`, `guards`, `assembly-memory`, `cross-cutting-replay`, `devops-supplychain`, `post-audit-diff`. Mỗi finder phải nêu file:line, đường tấn công, và danh sách giả thuyết đã loại bỏ.
3. Dedup: 30 finding thô gộp còn 28 (F01..F28).
4. Verify đối kháng: mức medium trở lên nhận 3 verifier (refute, exploit, impact); mức low nhận 2 (refute, impact); mức informational ở contract nhận 1 (impact); 10 finding về tài liệu/CI/tooling được chính orchestrator xác minh bằng grep, git log, npm audit. Tổng 28 verdict từ agent + 10 verdict tự xác minh. Finding được "xác nhận" khi đa số phiếu nói là thật; mức độ nghiêm trọng lấy theo đồng thuận của verifier, không lấy theo finder.
5. Critic: kiểm tra độ phủ (58/58 contract production được ít nhất một lens đọc), tính toàn bộ selector của các contract để loại trừ selector collision, rồi đề xuất 4 gap; 3 gap được chạy finder + verify, gap thứ 4 (điểm mù Certora) được đưa vào báo cáo từ dữ kiện critic đã xác lập.
6. Mọi khẳng định quan trọng đều có PoC chạy được trên hardhat tại HEAD, lưu trong `docs/security-review/poc/`.

## 3. Baseline đã kiểm chứng

- `npx hardhat test --network hardhat`: 465 passing, 7 pending tại HEAD (trước khi thêm PoC).
- `npm audit --omit=dev`: 0 advisory. `npm audit` đầy đủ: 79 advisory, toàn bộ ở devDependencies (`ws`, `uuid`, `tmp` qua `solc`, `axios`/`elliptic` qua `zksync-ethers`); không ảnh hưởng bytecode đã deploy.
- Build mặc định (solc 0.7.6, optimizer tắt) tái tạo chính xác toàn bộ địa chỉ trong bảng CHANGELOG 1.5.0 khi build đúng commit release (verifier F08 đã kiểm tra bằng CREATE2 với singleton factory).

## 4. PoC kèm theo (tất cả pass tại HEAD)

Chạy: `AUDIT_LOCAL_SOLC=1 npx hardhat test docs/security-review/poc/<file> --network hardhat` (biến môi trường chỉ cần khi máy không tải được solc; xem mục 12).

| File | Nội dung | Số test |
| --- | --- | --- |
| `eip7702-setup-frontrun.spec.ts` | EOA delegate tới singleton mà không `setup` nguyên tử bị chiếm quyền và rút tiền | 1 |
| `guards-reentrancy-debug.spec.ts` | `ReentrancyTransactionGuard`: callee mở khóa và re-enter, ai cũng khóa/mở được, chặn nested cross-Safe; `DebugTransactionGuard`: callee ép revert, va chạm nonce 0 | 5 |
| `libraries-parsing-edgecases.spec.ts` | Parser packed của MultiSend: dataLength quá dài, op không hợp lệ trả returndata cũ, byte thừa, dataLength khổng lồ, `getStorageAt` overflow, gọi trực tiếp singleton | 6 |
| `replay-lens.spec.ts` | Các kiểm tra "fail closed" về replay/domain binding: executor 0, approvedHashes sau khi gỡ owner, nested mutual Safe, validator đốt gas, precompile làm owner, tx-hash vs message-hash, executor shortcut, SignMessageLib | 8 |
| `post-audit-erc1271-strict-return.spec.ts` | Bảng so sánh ngữ nghĩa trả về ERC-1271 trước/sau #1115 (32/33/64/31/4/0 byte, dirty bits, magic lệch), EOA làm signer, validator đốt gas, nonce không bị tiêu, Safe lồng nhau vẫn hợp lệ | 12 |

Ngày: 2026-10-14. Toàn bộ file:line trong báo cáo đã được mở lại và đối chiếu tại HEAD trước khi viết (một số tham chiếu trong `hardhat.config.ts` và `SignatureVerifierMuxer.sol` do finder đưa ra bị lệch, đã sửa trong báo cáo này).

## 5. Tóm tắt

**Phạm vi.** 58 contract production dưới `contracts/` (trừ `contracts/test/**`), script deploy và task TypeScript dưới `src/`, `hardhat.config.ts`, CI (`.github/workflows/*.yml`), cấu hình Certora, `docs/*.md`, `CHANGELOG.md`. Build chuẩn là solc 0.7.6, optimizer tắt (số học unchecked, dùng SafeMath ở các chỗ quan trọng). Vùng mã được ưu tiên là các commit vào sau hai audit 1.5.0 (Certora `1c8b24a` 2025-01-23, Ackee `5d26505` 2025-05-27): `#998` self-ownership (2025-07-10), `#1019` `proxyCreationCodehash` (2025-07-11), `#1062` EIP-7702 (2025-12-12), `#1061` EIP-7951 secp256r1 (2026-01-14), `#1115` `SecuredSignatureValidator` (2026-06-05), `#1123` fix `simulate` (2026-09-24).

**Phương pháp.** 11 lens tìm kiếm độc lập (core-sig, gas-refund, managers, proxy-setup-migration, handlers, libraries, guards, assembly-memory, cross-cutting-replay, devops-supplychain, post-audit-diff), dedup còn 28 finding; critic kiểm tra độ phủ (58/58 contract được ít nhất một lens đọc, tính toàn bộ selector để loại trừ collision) rồi mở 3 gap lens (Enum.Operation dưới ABI coder v1, tổ hợp fallback handler khác version, owner secp256r1 đa chain) sinh thêm 8 finding. Mỗi finding mức medium trở lên nhận 3 verifier đối kháng (refute, exploit, impact), mức low nhận 2, mức informational nhận 1; các mục tài liệu/CI được orchestrator tự xác minh. Mức độ nghiêm trọng trong báo cáo lấy theo đồng thuận verifier, không lấy theo finder. Mọi khẳng định hành vi quan trọng có PoC chạy pass tại HEAD trong `docs/security-review/poc/*.spec.ts` hoặc test tạm đã xóa (ghi trong phần verifier).

**Baseline.** Full suite 465 passing tại HEAD. `npm audit --omit=dev`: 0 advisory (79 advisory chỉ ở devDependencies). Build mặc định tái tạo chính xác 13 địa chỉ CREATE2 trong CHANGELOG 1.5.0 khi build đúng commit release.

**Kết quả tổng thể.** Không có finding critical hoặc high. Không tìm thấy đường mất tiền hoặc mất quyền kiểm soát trên core Safe/SafeL2, proxy, factory, handler, library mà không cần owner hợp tác. 32 finding được xác nhận: 0 medium theo đồng thuận (F02 bị chia phiếu medium/low/informational), 7 low, 25 informational; 2 finding còn tranh cãi; 2 bị bác bỏ. Các finding low tập trung ở contract ví dụ (`contracts/examples/guards/*`), ở khoảng trống tài liệu/tương thích của các thay đổi sau audit, và một hiện tượng gas-accounting lâu năm. Hai commit ít được review nhất (`#1115`, `#1123`) được xác nhận đúng về mặt cài đặt; vấn đề còn lại của chúng là test coverage và tài liệu.

**Confidence tổng thể: 0.8** rằng bức tranh trên là đúng và đầy đủ ở mức một review độc lập có thể đạt được (xem mục 12 cho giới hạn).

## 6. Bảng tổng hợp

| ID | Tiêu đề rút gọn | Mức độ (đồng thuận) | Conf. | Vị trí | Trạng thái |
|---|---|---|---|---|---|
| F01 | `ReentrancyTransactionGuard`: ai cũng khóa/mở được cờ, callee có thể gỡ khóa rồi re-enter | low (medium nếu deploy nguyên bản) | 0.9 | `contracts/examples/guards/ReentrancyTransactionGuard.sol:57-59, 66-68` | Xác nhận 3/3 |
| F02 | EIP-7702 delegate thẳng tới singleton: `setup()` chỉ chặn bằng `threshold > 0`, flow không nguyên tử hoặc sponsored bị chiếm | chia phiếu: medium / low / informational | 0.65 | `contracts/Safe.sol:108-117`, `contracts/base/OwnerManager.sol:49` | Xác nhận 2/3 |
| F03 | `DebugTransactionGuard.checkAfterExecution` không kiểm tra caller, callee ép toàn bộ tx revert | low | 0.85 | `contracts/examples/guards/DebugTransactionGuard.sol:84-89` | Xác nhận 2/2 |
| F04 | Regression `#1062`: self-owner cũ (Safe <=1.2.0) không gỡ/swap được sau khi lên 1.5.0 (GS203) | low | 0.85 | `contracts/base/OwnerManager.sol:118-122, 139-143` | Xác nhận 2/2 |
| F06 | `local-verify` chỉ in FAILURE, pipeline deploy vẫn tiếp tục | low / informational (chia phiếu) | 0.7 | `src/tasks/local_verify.ts:41-42`, `src/tasks/deploy_contracts.ts:4-7` | Xác nhận 2/2 |
| F07 | Ngưỡng GS010 không tính phí CALL (cold access, value), callee có thể nhận ít hơn `safeTxGas` | low | 0.8 | `contracts/Safe.sol:197, 203`, `contracts/base/Executor.sol:40` | Xác nhận 2/2 |
| F09 | `docs/signatures.md` thiếu kiểu chữ ký `v == 2` (secp256r1) | informational | 0.95 | `docs/signatures.md:13-69` | Xác nhận |
| F10 | MultiSend: operation không hợp lệ revert với returndata của sub-call trước | informational | 0.9 | `contracts/libraries/MultiSend.sol:61-73` | Xác nhận |
| F11 | Parser packed MultiSend không kiểm tra bound (off-by-32, dataLength quá dài) | informational | 0.9 | `contracts/libraries/MultiSend.sol:39-43, 58, 75` | Xác nhận |
| F12 | `DebugTransactionGuard` dùng nonce 0 làm sentinel | informational | 0.9 | `contracts/examples/guards/DebugTransactionGuard.sol:72, 86` | Xác nhận |
| F13 | Các thay đổi sau audit ngoài #1115/#1123 không có trong CHANGELOG/audit | informational | 0.9 | `CHANGELOG.md:8-16` | Xác nhận |
| F14 | Ngữ nghĩa return-data nghiêm ngặt của #1115 chưa có test | informational | 0.9 | `test/core/Safe.Signatures.spec.ts:1102-1144` | Xác nhận |
| F15 | Offset chữ ký gần 2^256 revert rỗng qua SafeMath thay vì GS022/GS023/GS027 | informational | 0.9 | `contracts/Safe.sol:272, 282, 368` | Xác nhận |
| F16 | CI thiếu `permissions:`, action pin theo tag | informational | 0.9 | `.github/workflows/ci.yml:2, 10-76` | Xác nhận |
| F17 | `docs/error_codes.md` GS024 lỗi thời, GS027 tái sử dụng khác nghĩa 1.3.0 | informational | 0.7 | `docs/error_codes.md:41-43, 50` | Xác nhận |
| F18 | Dev toolchain có package lỗi (axios 0.21.4, elliptic 6.5.4), không chạm on-chain | informational | 0.9 | `package.json:71` | Xác nhận |
| F19 | Certora workflow tải solc không checksum, pip không hash, job giữ `CERTORA_KEY` | informational | 0.85 | `.github/workflows/certora.yml:28, 32-34, 45` | Xác nhận |
| F20 | `ExtensibleFallbackHandler.onlySelf`: địa chỉ bất kỳ tự đăng ký như "Safe" | informational | 0.75 | `contracts/handler/extensible/ExtensibleBase.sol:35-41` | Xác nhận |
| F21 | Mnemonic mặc định công khai dùng cho live network khi thiếu MNEMONIC/PK | informational | 0.8 | `hardhat.config.ts:65-69, 77` | Xác nhận |
| F22 | `local-verify`/`yulcode` chạy solc-js tải từ xa không kiểm tra integrity | informational | 0.8 | `src/utils/solc.ts:13` | Xác nhận |
| F23 | Native payment trong `setup()` thành 0 khi `tx.gasprice == 0` | informational | 0.85 | `contracts/Safe.sol:129-133, 252` | Xác nhận |
| F25 | NatSpec `SignMessageLib` mô tả đường verify đã bị gỡ từ 1.4.0 | informational | 0.9 | `contracts/libraries/SignMessageLib.sol:27` | Xác nhận |
| F26 | Cấu hình per-Safe của EFH sống trong storage handler, không enumerable, tồn tại qua đổi handler/owner | informational | 0.75 | `contracts/handler/extensible/SignatureVerifierMuxer.sol:64, 79-84` | Xác nhận |
| F27 | Escape hatch solc của chính review (fork-only) bỏ qua integrity check của Hardhat | informational | 0.9 | `hardhat.config.ts:19-40` | Xác nhận |
| F28 | MultiSend remap `to == 0` thành `address(this)`: khác ngữ nghĩa <=1.4.1, chưa ghi CHANGELOG | informational | 0.85 | `contracts/libraries/MultiSend.sol:54`, `MultiSendCallOnly.sol:45` | Xác nhận |
| G1-1 | Enum.Operation ngoài khoảng: 0.7.6 chỉ chặn bằng INVALID (đốt hết gas, không mã lỗi); 0.8 chặn lúc decode | informational | 0.9 | `contracts/base/Executor.sol:29`, `contracts/Safe.sol:175` | Xác nhận |
| G1-2 | CI chỉ chạy benchmark happy-path trên 0.8.24, không chạy test suite | informational (finder: low) | 0.8 | `.github/workflows/ci.yml:62-84`, `package.json:27` | Xác nhận |
| G1-3 | `getTransactionHash` và helper TS chấp nhận mọi uint8 operation; 0.7.6 mask dirty bits | informational | 0.9 | `contracts/Safe.sol:529`, `src/utils/execution.ts:19, 276` | Xác nhận |
| G2-1 | Handler 1.5.0 (CFH/EFH) không verify ERC-1271 trên Safe 1.3.0/1.4.1 dù NatSpec nói tương thích | low | 0.85 | `contracts/handler/CompatibilityFallbackHandler.sol:11, 83`, `SignatureVerifierMuxer.sol:159` | Xác nhận |
| G2-2 | Safe 1.5.0 + CFH 1.5.0 không thể làm contract-signer owner của Safe 1.3.0/1.4.1 | low | 0.85 | `contracts/handler/CompatibilityFallbackHandler.sol:73` | Xác nhận |
| G2-3 | `migrateSingleton` mất `encodeTransactionData`; hai entry point migration bảo toàn hai tập legacy loại trừ nhau; migration test không chạm ERC-1271 | informational | 0.8 | `contracts/libraries/SafeMigration.sol:71-83` | Xác nhận |
| G3-1 | Owner secp256r1 làm liveness phụ thuộc precompile 0x100; Safe đa chain counterfactual có thể bị khóa | informational (finder: low) | 0.65 | `contracts/base/OwnerManager.sol:118-122`, `contracts/common/EIP7951.sol:39-44` | Xác nhận |
| F05 | Cờ `ReentrancyTransactionGuard` toàn cục per deployment; NatSpec sai | informational | 0.6 | `ReentrancyTransactionGuard.sol:12, 26` | Tranh cãi 1/2 |
| F08 | Không có guard bắt buộc compiler settings chuẩn khi deploy live; `local-verify` tự tham chiếu | low / informational | 0.55 | `hardhat.config.ts:80, 109-111` | Tranh cãi 1/2 |
| F24 | `onlySelf` giả mạo được nếu EFH cài trên Safe <1.3.0 | bác bỏ: hành vi đã được tài liệu hóa | 0.85 | `contracts/handler/HandlerContext.sol:41-44` | Bác bỏ 0/1 |
| G3-2 | `p256Verify` chỉ test với emulation EDR | bác bỏ: chỉ là khoảng trống test | 0.9 | `contracts/common/EIP7951.sol:39-44` | Bác bỏ 0/1 |

## 7. Chi tiết các finding đã xác nhận

### F01. `ReentrancyTransactionGuard`: không có kiểm tra `msg.sender`, cờ khóa bị gỡ hoặc đặt bởi bất kỳ ai

**Mức độ:** low theo cả 3 verifier (impact, refute, exploit); medium nếu integrator deploy nguyên bản. Finder đề xuất medium. **Confidence: 0.9.**

**Mô tả.** Guard giữ một boolean tại slot hằng `GUARD_STORAGE_SLOT` trong storage của chính guard (`:12`, đọc qua `getGuard()` `:29-37`). `checkTransaction` (`:57-59`) làm `require(!guard.active); guard.active = true;`, `checkAfterExecution` (`:66-68`) làm `getGuard().active = false;`, hai hook module (`:87-89`, `:96-98`) dùng cùng slot. Không hàm nào kiểm tra caller là Safe đã cấu hình guard.

**Đường tấn công / điều kiện.**
- Bypass: Safe S cài guard G; owner đã ký T1 (nonce n, `to` là contract A chạm được mã kẻ tấn công) và T2 (nonce n+1, ví dụ cùng hàng chờ trong transaction service nơi chữ ký công khai). Relayer thực thi T1: `Safe.sol:168` nonce thành n+1, `:170` checkSignatures, `:175` G.checkTransaction đặt `active=true`, `:203` execute gọi A. A gọi thẳng `G.checkAfterExecution(bytes32(0), false)` (không có kiểm tra caller) rồi gọi `S.execTransaction(T2)`: chữ ký hợp lệ, guard thấy `active==false`, T2 chạy lồng trong T1. Mục đích duy nhất của guard ("Prevents reentrancy into the transaction execution function", `:8`) không còn đúng với bất kỳ callee nào. Biến thể qua `checkAfterModuleExecution` cũng được xác nhận.
- Griefing: EOA bất kỳ gọi `G.checkTransaction(...)` với tham số rỗng để đặt cờ; mọi Safe dùng instance G revert "Reentrancy detected" cho đến khi ai đó gọi `checkAfterExecution` (cũng permissionless). Kẻ tấn công có thể khóa lại mỗi block. Refute lens chỉ ra relayer có thể bundle unlock + exec trong một tx, nên DoS này khắc phục được ngay trong cùng một giao dịch (đã test).

**Bằng chứng.** `ReentrancyTransactionGuard.sol:57-59`, `:66-68` như trên; `Safe.sol:168` (nonce++ trước thực thi), `:175-190`, `:203`, `:226-228`. Các guard ví dụ khác có ràng buộc Safe gọi (`OnlyOwnersGuard.sol:41`, `DebugTransactionGuard.sol:71, 75`). PoC: `docs/security-review/poc/guards-reentrancy-debug.spec.ts`, test "a callee can clear the lock and re-enter execTransaction (guard bypass)" (control không có unlock revert "Reentrancy detected"; có unlock thì `mock.invocationCount()==1`, `safe.nonce()==n+2`) và "anyone can lock the guard (DoS for every Safe using it) and anyone can unlock it".

**Khuyến nghị.** Key cờ theo Safe gọi và chỉ cho Safe đó gỡ: `mapping(address => bool) active; require(!active[msg.sender]); active[msg.sender] = true;` trong hai hook trước, `active[msg.sender] = false;` trong hai hook sau. Hoặc ghi rõ trong header contract và `docs/overview.md` rằng ví dụ này không deploy nguyên bản được.

**Ghi chú verifier.** Cả ba xác nhận cơ chế; hạ xuống low vì `examples/README.md:3` và `CHANGELOG.md:687` đánh dấu non-production, Ackee 1.5.0 loại `contracts/examples` khỏi scope, không script deploy nào ship guard, bypass chỉ gỡ một lớp bảo vệ opt-in và T2 vẫn phải là tx đã được ký. `CHANGELOG.md:691` chỉ thừa nhận việc chia sẻ cờ giữa các Safe (F05), không thừa nhận việc thiếu kiểm tra caller. Exploit lens chạy thêm test tạm: lock chặn cả `setGuard(0)` của owner; bypass qua module guard; unlock chéo giữa hai đường.

### F02. EIP-7702 delegate thẳng tới singleton Safe/SafeL2: `setup()` chỉ được chặn bởi `threshold == 0`

**Mức độ:** verifier chia phiếu: exploit medium (0.9), impact low (0.7), refute informational và coi đây là thuộc tính vốn có đã được thừa nhận (0.8). Đa số 2/3 nói là thật. Báo cáo ghi nhận cả ba và coi đây là **integration hazard được tài liệu hóa chưa đủ, mức low theo median**. **Confidence: 0.65.**

**Mô tả.** Singleton 1.5.0 được thiết kế để là EIP-7702 delegation target (`contracts/common/EIP7702.sol:15-28`; `OwnerManager.sol:120` cho phép `owner == address(this)` khi `isThisDelegatedAccount()`; `ISafe.sol:58` nói self-ownership "is a valid setup for EIP-7702 delegations"). Nhưng `setup()` (`Safe.sol:108-117`, `external`, không kiểm tra caller) chỉ bị chặn bởi `if (threshold > 0) revertWithError("GS200")` ở `OwnerManager.sol:49`; `threshold = 1` trong constructor (`Safe.sol:99-103`) chỉ ghi vào storage của singleton. EOA vừa delegate có `threshold == 0` và `modules[SENTINEL] == 0` (`ModuleManager.sol:88-90`) nên `setup()` gọi được bởi bất kỳ `msg.sender` nào. Với proxy CREATE2, factory gọi initializer nguyên tử (`SafeProxyFactory.sol:66-77`); không có cơ chế tương đương cho 7702, và EOA 7702 đã sẵn có tài sản nên chiếm quyền là có lợi ngay. Thừa nhận duy nhất trong repo là comment trong helper test `test/utils/setup.ts:122-123` ("UNSAFE ... can be front-run by anyone").

**Đường tấn công / điều kiện.**
- Sponsored flow: nạn nhân ký authorization tuple {chainId, singleton, nonce} cho relayer. Tuple EIP-7702 không ràng buộc với sender của transaction, nên kẻ tấn công thấy tuple (mempool, API relayer) gửi type-4 tx riêng `{authorizationList:[tuple], to: victim, data: setup([attacker],1,...)}` với priority fee cao hơn; trở thành owner duy nhất; tx của relayer sau đó fail (nonce authorization cũ + GS200); rút tiền qua `execTransaction`.
- Flow không nguyên tử (delegate ở tx này, setup ở tx sau, đúng như helper test mô phỏng): kẻ tấn công gọi `victimEOA.setup([attacker], 1, ...)` trong khoảng trống.
- Flow an toàn tồn tại: EOA tự gửi type-4 tx với `to = self`, `data = setup(...)`, authorization nonce + 1 (impact lens đã test: miễn nhiễm).

**Bằng chứng.** Các dòng trên; `grep isThisDelegatedAccount` chỉ ra `OwnerManager.sol:120` là nơi dùng duy nhất. PoC `docs/security-review/poc/eip7702-setup-frontrun.spec.ts`, test "attacker can take over a freshly delegated EOA and drain it" pass. Exploit lens chạy thêm test tạm cho sponsored hijack: kẻ tấn công dùng lại tuple của nạn nhân, code tại victim là `0xef0100||singleton`, setup của relayer sau đó revert.

**Khuyến nghị.** Tối thiểu ghi rõ trong NatSpec `ISafe.setup`, `docs/overview.md` và CHANGELOG 1.5.0: không dùng singleton làm delegation target trực tiếp trừ khi `setup` chạy nguyên tử trong type-4 tx tự gửi; authorization do relayer bảo trợ có thể bị chiếm; trỏ tới `safe-eip7702` proxy (commit hash setup data vào delegate bytecode). Cân nhắc in-code: `if (isThisDelegatedAccount() && msg.sender != address(this)) revertWithError(...)` trong `setup()`, lưu ý impact lens cho rằng mitigation này phá flow relayer-sponsored và wrapper delegate nên không cân xứng.

**Ghi chú verifier.** Refute lens: đây là thuộc tính vốn có của mọi initializer dưới EIP-7702, `ISafe.sol:57` đã cảnh báo proxy chưa setup, Ackee 1.5.0 nói bản được review không tương thích EIP-7702 và self-ownership vào sau audit, nên chỉ cần ghi chú tài liệu. Exploit lens giữ medium vì tuple không ràng buộc sender nên ngay cả flow sponsored "định nguyên tử" cũng bị chiếm được.

### F03. `DebugTransactionGuard.checkAfterExecution` permissionless, callee ép toàn bộ Safe tx revert

**Mức độ:** low (2/2). **Confidence: 0.85.**

**Mô tả.** `checkTransaction` lưu `txNonces[txHash] = nonce` (`:76`); `checkAfterExecution` (`:84-89`) làm `require(nonce != 0, "Could not get nonce"); txNonces[txHash] = 0;` không kiểm tra `msg.sender`. Callee của Safe tx tính lại được txHash (biết `to`, `value`, `data`, gas params thấy trong pending tx, `ISafe(msg.sender).getTransactionHash(..., nonce()-1)`), gọi `guard.checkAfterExecution(H, false)` để xóa record; khi `Safe.sol:227` gọi thật, `require` fail và toàn bộ `execTransaction` revert. Bình thường, tx với `safeTxGas>0` hoặc `gasPrice>0` chịu được callee fail (`Safe.sol:207` chỉ revert khi cả hai bằng 0, ghi `ExecutionFailure`, vẫn trả refund, tiêu nonce); với guard này, callee biến ngữ nghĩa fail-safe thành revert do callee kiểm soát: relayer không được trả, nonce không tiêu, tx có thể bị grief lặp lại.

**Bằng chứng.** `DebugTransactionGuard.sol:84-89` như trên; `Safe.sol:207, 219-223, 226-227`. PoC: `guards-reentrancy-debug.spec.ts`, test "a callee can force the whole Safe transaction to revert via permissionless checkAfterExecution" (revert "Could not get nonce"). Impact lens chạy thêm test tạm: nonce không đổi, không refund cho relayer.

**Khuyến nghị.** Key `txNonces` theo Safe (`mapping(address => mapping(bytes32 => uint256))` theo `msg.sender`), hoặc bỏ hẳn `require` và storage round-trip (tính lại nonce từ `msg.sender.nonce()` khi emit), vì guard debug không bao giờ nên có khả năng làm Safe revert.

**Ghi chú verifier.** Cả hai đồng ý là lỗi đúng nghĩa trong ví dụ, giới hạn low vì là dev tool (`:10`), không được deploy, phục hồi bằng `setGuard(0)`.

### F04. Regression `#1062`: self-owner legacy không gỡ/swap được sau khi migrate lên 1.5.0

**Mức độ:** low (2/2). **Confidence: 0.85.**

**Mô tả.** `removeOwner` (`OwnerManager.sol:93`) và `swapOwner` (`:106`) gọi `requireCanRemoveOwner` (`:139-143`), hàm này gọi `requireIsValidOwner(owner)` (`:118-122`), revert GS203 khi `owner == address(this) && !isThisDelegatedAccount()`. Trước `#1062` (xem `git show 0227664 -- contracts/base/OwnerManager.sol`) kiểm tra khi gỡ chỉ là `owner != 0 && owner != SENTINEL`; 1.3.0/1.4.1 cũng không chặn. Safe 1.1.1/1.2.0 cho phép Safe tự làm owner. Safe cũ có self-owner, migrate lên 1.5.0 (qua `changeMasterCopy` hoặc `SafeMigration`), sẽ có owner "ma" không ký được, đếm vào `ownerCount`, không gỡ/swap được. Ý định của `#1062` là chặn thêm self-owner, chặn gỡ là tác dụng phụ. Không mất tiền: tự phê duyệt `v==1` cần `msg.sender == Safe`, handler truyền executor `address(0)` (`CompatibilityFallbackHandler.sol:83`).

**Bằng chứng.** Các dòng trên. Test tạm của finder và hai verifier (đã xóa) trên bytecode 1.1.1/1.2.0/1.4.1 trong `test/json/safeDeployment.json`: 1.1.1 `setup([user1, proxy], 1)` thành công, lên 1.5.0 thì `removeOwner(user1, proxy, 1)` và `swapOwner(user1, proxy, user2)` revert GS203, `addOwnerWithThreshold` vẫn chạy; lên 1.4.1 thì gỡ được. `test/migration/*` chỉ migrate Safe một EOA owner nên không bắt được.

**Khuyến nghị.** Trong `requireCanRemoveOwner` bỏ điều kiện `address(this)` cho owner bị gỡ (giữ null/sentinel + kiểm tra linked list GS205). Thêm migration test cho Safe <=1.2.0 có self-owner. Nếu cố ý giữ, ghi trong CHANGELOG/migration notes.

**Ghi chú verifier.** Refute lens chỉ bác được từ "permanently": phục hồi được qua delegatecall vào library có layout SafeStorage, hoặc hạ xuống 1.4.1 bằng `SafeMigration` 1.4.1 rồi gỡ rồi lên lại (impact lens demo). Impact lens thêm: self-owner tồn đọng làm `ownerCount` phồng, `changeThreshold(3)` với 2 signer thật thành công rồi mọi tx fail GS020 (demo).

### F06. `local-verify` không bao giờ làm fail pipeline deploy

**Mức độ:** impact low (0.7), refute informational (0.75). Ghi nhận là **low/informational**. **Confidence: 0.7.**

**Mô tả.** `local-verify` là bước duy nhất so sánh code on-chain với artifact local. Nó tính `verifySuccess = ... ? "SUCCESS" : "FAILURE"` (`src/tasks/local_verify.ts:41`) rồi chỉ `console.log` (`:42`), không throw, không set `process.exitCode`. Task tổng hợp `deploy-contracts` (`src/tasks/deploy_contracts.ts:4-7`) chạy `deploy` -> `local-verify` -> `sourcify` -> `etherscan-verify` tuần tự không kiểm tra kết quả. hardhat-deploy (deterministic path, `fetchIfDifferent`) coi địa chỉ CREATE2 có code là "đã deploy" mà không so bytecode. `README.md:65-73` mô tả `local-verify` là bước cuối nhưng code chạy nó trước các bước upload.

**Điều kiện.** Vận hành, không có kẻ tấn công: chain có CREATE2/factory lệch chuẩn, hoặc file `deployments/<network>/*.json` cũ/hỏng. Refute lens lưu ý CREATE2 ràng buộc keccak(initcode) nên FAILURE cần EVM lệch chuẩn hoặc metadata hỏng, Sourcify/Etherscan cũng recompile phía server, và `README.md:44-46` đặt PR thủ công vào safe-deployments làm cổng kiểm soát.

**Khuyến nghị.** Gom lỗi và `throw` (hoặc `process.exitCode = 1`) cuối `local-verify` khi có FAILURE để `deploy-contracts` dừng trước `sourcify`/`etherscan-verify`; đồng bộ thứ tự bước với README.

### F07. Ngưỡng GS010 bỏ qua phí ở mức CALL, callee có thể nhận ít hơn `safeTxGas`

**Mức độ:** low (2/2). **Confidence: 0.8.**

**Mô tả.** Tài liệu (`docs/safe_tx_gas.md:21, 39`; comment `Safe.sol:194-196`) hứa rằng qua được GS010 thì inner call nhận ít nhất `safeTxGas`, relayer không ảnh hưởng được kết quả. Check `gasleft() >= max(safeTxGas*64/63, safeTxGas+2500) + 500` (`Safe.sol:197`) chỉ dự trù 500 gas cho mã trước thực thi. Nó không tính phí EVM thu ở caller tại opcode CALL (`Executor.sol:40`) trước khi áp 63/64: cold account access 2600 (EIP-2929), value transfer 9000, new account 25000, và copy calldata->memory của `data` tại `Safe.sol:203` (~3 gas/word). Với gasleft tại `:197` đúng bằng ngưỡng, callee nhận `safeTxGas - D`, D ~2.4K (cold, không value), ~9K (có value), ~33K (value tới tài khoản trống). Vì fail với `safeTxGas>0` không revert ngoài (`:207`), nonce bị tiêu (`:168`), `ExecutionFailure` emit (`:223`), refund vẫn trả (`:220`).

**Điều kiện.** Refund mode với `safeTxGas` đủ lớn để 1/64 giữ lại đủ trả handlePayment + event (~700K gas native refund; ~150K ở no-refund mode), `to` cold, và ước lượng `safeTxGas` sát nhu cầu thật trong khoảng D. Người submit chọn gasLimit sao cho gasleft tại `:197` vừa đủ ngưỡng.

**Bằng chứng.** Dòng mã trên. Impact lens test tạm (bisection `evm_snapshot`): callee gasleft 299.800 với gas dư so với 297.354 tại mép GS010 (thiếu 2.446); callee cần 298.577 thành công bình thường nhưng fail ở mép, nonce +1, refund đã trả. Refute lens: thiếu 2.448 (cold, value 0), 9.210 net stipend (value 1), 2.444 ở no-refund; warm `to` bằng EIP-2930 access list đưa thiếu hụt về đúng 0, chứng minh mục chưa tính là phí cold access hậu Berlin (hằng số từ 2020 chưa được tinh chỉnh). Ước lượng từ `SimulateTxAccessor` dùng nguyên vẫn thành công với 535 gas dư. Test hiện có `test/core/Safe.Execution.spec.ts:257` có FIXME về gas quanh biên nhưng không có test boundary. G0 Group 1.2.0 issue 1 từng xếp lớp này là bug.

**Khuyến nghị.** Tính thêm phí CALL vào pre-check (ví dụ `+ 2600 + (operation == Call && value > 0 ? 34000 : 0) + 3 * ((data.length + 31) / 32)`), hoặc chuyển `gasleft()` check xuống ngay trước CALL trong `execute`. Tối thiểu ghi trong `docs/safe_tx_gas.md` rằng signer phải cộng buffer ~2.6K/9K/34K + 3 gas/word, và thêm boundary test với `to` cold.

### F09. `docs/signatures.md` không mô tả kiểu chữ ký `v == 2` (secp256r1, RIP-7212/EIP-7951)

**Mức độ:** informational. **Confidence: 0.95.**

`docs/signatures.md:13-69` chỉ liệt kê ECDSA (`31 > type > 26`, `:15`), eth_sign (`> 30`, `:27`), contract (`== 0`, `:39`), pre-validated (`== 1`, `:61`). `Safe.sol:354-396` còn nhánh `v == 2`: phần tĩnh `{owner}{data pointer}{0x02}`, phần động cố định 128 byte `{r}{s}{qx}{qy}` không có length prefix (`:367-368` GS021/GS027), owner = `keccak256(qx||qy)[12:]` (`:393`), không ép low-s. Parser off-chain viết theo spec sẽ hiểu sai `v == 2`. **Khuyến nghị:** thêm mục "secp256r1 signature (signature type == 2)" mô tả đúng layout, cách suy địa chỉ, và malleability chấp nhận. Không có đường tấn công on-chain.

### F10. MultiSend / MultiSendCallOnly: operation không hợp lệ revert với returndata cũ

**Mức độ:** informational. **Confidence: 0.9.**

`switch operation` chỉ có `case 0`/`case 1` (`MultiSend.sol:62-68`, `MultiSendCallOnly.sol:53-60`); op khác giữ `success = 0` rồi `returndatacopy(ptr, 0, returndatasize()); revert(...)` (`MultiSend.sol:69-73`, `MultiSendCallOnly.sol:61-65`), mà buffer returndata lúc đó còn chứa output của sub-call thành công trước đó (EIP-211). Batch vẫn revert toàn bộ (atomicity giữ), chỉ sai lý do revert. PoC: `libraries-parsing-edgecases.spec.ts`, test "invalid operation reverts with the *previous* sub-call's return data (stale returndata)": entry 1 trả `Error("NOT A REVERT")`, entry 2 op=2, batch revert với `Error("NOT A REVERT")`. Test hiện có chỉ phủ trường hợp entry đầu. **Khuyến nghị:** thêm `default { revert(0, 0) }` và test hai entry.

### F11. Parser packed của MultiSend không kiểm tra bound

**Mức độ:** informational. **Confidence: 0.9.**

`length := mload(transactions)` là độ dài không header, cursor `i` bắt đầu 0x20 và điều kiện `lt(i, length)` (`MultiSend.sol:39-43`, `MultiSendCallOnly.sol:30-34`) so offset có header với độ dài không header (lệch 32 byte, che khuất vì mỗi entry >= 85 byte). `dataLength` (`:58`) không được kiểm tra với phần còn lại; cursor advance (`:75`) không kiểm tra. Kết quả được PoC xác nhận: dataLength quá dài đọc memory zero-filled sau array (không thực thi rác), 1..31 byte thừa bị bỏ qua, 33..84 byte thừa được parse thành entry cụt với field thiếu bằng 0 (`to` = 0 bị remap thành `address(this)` tại `:54`), dataLength khổng lồ OOG trước khi cursor wrap. Payload là owner-signed; hành vi giống MultiSend gốc, cả hai audit 1.5.0 có file trong scope, Certora 1.3.0 I-01 đã acknowledge. PoC: ba test "over-long dataLength ...", "trailing bytes shorter than 32 ...", "huge dataLength cannot wrap the cursor ..." pass. **Khuyến nghị:** nếu muốn nghiêm ngặt, loop tới `end := add(0x20, length)` và `require(i + 0x55 + dataLength <= end)`; nếu không, ghi hành vi lenient vào NatSpec để decoder SDK/UI mô phỏng đúng.

### F12. `DebugTransactionGuard` dùng nonce 0 làm sentinel "chưa ghi"

**Mức độ:** informational. **Confidence: 0.9.**

`nonce = safe.nonce() - 1` (`:72`), lưu `:76`, `require(nonce != 0)` (`:86`). Tx đầu tiên của Safe (nonce 0) luôn revert "Could not get nonce" nếu guard được cài mà không tiêu nonce (qua module `execTransactionFromModule -> setGuard`, hoặc delegatecall library lúc setup). PoC: test "nonce 0 collides with the 'not set' sentinel when the guard is installed without consuming a nonce". Tự gây, phục hồi qua đường cùng loại. **Khuyến nghị:** lưu `nonce+1` hoặc cờ `seen`; cùng refactor với F03.

### F13. Các thay đổi chức năng sau audit ngoài #1115/#1123 không có trong audit 1.5.0, CHANGELOG "Current version" và `docs/signatures.md`

**Mức độ:** informational. **Confidence: 0.9.**

`git diff 5d26505 HEAD -- contracts/` chứa ngoài #1115/#1123: (1) signer type `v == 2` EIP-7951 (`Safe.sol:354-396`, file mới `contracts/common/EIP7951.sol`, mã lỗi GS027/GS028; commit `0e91d99` 2026-01-14); (2) EIP-7702 self-ownership qua `isThisDelegatedAccount()` (`OwnerManager.sol:118-121`, file mới `EIP7702.sol`; `034184d` 2025-07-10, `0227664` 2025-12-12); (3) `SafeProxyFactory.proxyCreationCodehash` (`:42-44`, `1036b92`); (4) assembly `domainSeparator` (`Safe.sol:456-474`); (5) dời hằng slot sang `SafeStorage.sol`. Keyword search hai PDF audit 1.5.0: 0 hit cho 7951/secp256r1/p256; Ackee ghi "incompatible with EIP-7702". `CHANGELOG.md:8-16` chỉ ghi #1115. Tiền đề của brief rằng chỉ #1115 và #1123 vào sau audit không được lịch sử git ủng hộ. Không xác định được singleton 1.5.0 đã deploy (`0xFf51A5898e...`) có chứa các thay đổi này hay không (RPC bị chặn); `VERSION` vẫn "1.5.0" (`Safe.sol:58`). **Khuyến nghị:** bổ sung CHANGELOG cho #1061/#998/#1062/#1019; thêm secp256r1 vào `docs/signatures.md`; ghi rõ `docs/audit_1_5_0.md` không phủ các commit này hoặc tiến hành audit bổ sung; các review sau coi `Safe.sol:354-396`, `EIP7951.sol`, `EIP7702.sol`, `OwnerManager.sol:114-144` là mã chưa audit.

### F14. Ngữ nghĩa return-data nghiêm ngặt của #1115 chưa có test (chỉ test trường hợp revert)

**Mức độ:** informational. **Confidence: 0.9.**

Test #1115 thêm chỉ có hai case "isValidSignature reverts" (`test/core/Safe.Signatures.spec.ts:1102-1144`, `test/handlers/CompatibilityFallbackHandler.spec.ts:232-281`). Không test cho 33/64 byte (trailing), 31/4/0 byte (short), dirty low bits, magic lệch phải, EOA làm signer `v == 0`. PoC `docs/security-review/poc/post-audit-erc1271-strict-return.spec.ts` (12 passing) xác nhận `SecuredSignatureValidator.sol:23` chấp nhận đúng `0x1626ba7e || 28 byte 0` và từ chối (GS024) mọi biến thể khác, và bằng caller high-level legacy biên dịch cùng solc chứng minh mã trước #1115 chấp nhận 33/64 byte và dirty low bits đúng như CHANGELOG nói. Refactor tương lai (nới `== 32` thành `>= 32`, hoặc dùng abi.decode) sẽ không bị test bắt. **Khuyến nghị:** port các case của PoC vào suite chính.

### F15. Offset chữ ký gần 2^256 revert rỗng thay vì GS022/GS023/GS027

**Mức độ:** informational. **Confidence: 0.9.**

`Safe.sol:272` `offset.add(32)`, `:282` `offset.add(32).add(contractSignatureLen)`, `:368` `uint256(s).add(128)` dùng SafeMath trước khi so sánh; với `s >= 2^256 - 32` (v=0), length word khổng lồ, hoặc `s >= 2^256 - 128` (v=2), SafeMath revert trước. Hiệu chỉnh của verifier: `contracts/external/SafeMath.sol:24, 36, 48` dùng `require` không có chuỗi nên revert **rỗng** (đã xác nhận bằng test tạm); finder ban đầu ghi nhầm thành chuỗi "SafeMath: addition overflow". Mẫu này đã có sẵn qua `requiredSignatures.mul(65)` (`:319, 341, 367`) và có trước #1115; revert là toàn phần, không ảnh hưởng mục tiêu của #1115. **Khuyến nghị:** so sánh không overflow (`offset > signatures.length || signatures.length - offset < 32`) nếu muốn mọi đường chữ ký lỗi đều ra mã GS.

### F16. CI workflow thiếu `permissions:` tối thiểu, action pin theo major tag

**Mức độ:** informational. **Confidence: 0.9.**

`ci.yml:2` `on: [push, pull_request]`, không có `permissions:` ở workflow nào; `actions/checkout@v5` (`:10, 22, 35, 53, 75`), `setup-node@v4/@v6/@v5` (`:11, 23, 36, 54, 76`), `setup-python@v6` (`certora.yml:24`). Fork PR chỉ nhận token read-only; `ci.yml` không dùng secret; rủi ro là tag upstream bị retarget chạy với token mặc định. **Khuyến nghị:** `permissions: { contents: read }` ở top-level cả hai workflow; pin SHA (Dependabot/Renovate cập nhật); thống nhất version setup-node.

### F17. `docs/error_codes.md` lỗi thời sau các thay đổi hậu audit

**Mức độ:** informational. **Confidence: 0.7.**

(a) `docs/error_codes.md:41-43` mô tả GS024 là "contract signer returned an invalid value"; sau #1115 (`Safe.sol:295` + `SecuredSignatureValidator.sol:22-23`) GS024 còn bao gồm `isValidSignature` revert/OOG, địa chỉ không có code (staticcall không EXTCODESIZE check, PoC "EOA used as a v=0 contract signer => GS024"), và return data không đúng 32 byte; GS025/GS026 của Safe lồng nhau nay nổi lên là GS024 (`Safe.Signatures.spec.ts:514-516`). (b) GS027 được 1.3.0 định nghĩa là "dataHash must equal hash of data" (`CHANGELOG.md:300`), nay tái sử dụng cho "Invalid secp256r1 signature location" (`Safe.sol:368`, `error_codes.md:50`) không ghi chú. **Khuyến nghị:** cập nhật mục GS024 với đầy đủ trigger và mapping nested-Safe; ghi chú tái sử dụng GS027.

### F18. Dev toolchain có package lỗi, không chạm mã on-chain

**Mức độ:** informational. **Confidence: 0.9.**

`npm audit`: 79 advisory (4 critical, 45 high) toàn bộ devDependencies; `npm audit --omit=dev`: 0. `hardhat-deploy@1.0.4` (`package.json:71`) kéo `axios@0.21.4` (Etherscan API) và `zksync-ethers@5.11.0 -> ethers@5.7.2 -> elliptic@6.5.4` (chỉ dùng khi `zksync: true`, config không đặt; ký deploy đi qua provider local-accounts của Hardhat). `@openzeppelin/contracts@3.4.2` chỉ được `contracts/test/*` import. Lockfile sạch (v3, mọi package có integrity, nguồn registry.npmjs.org, CI dùng `npm ci`). **Khuyến nghị:** bump `hardhat-deploy` khi có bản bỏ axios 0.21.x/zksync-ethers 5.x hoặc dùng `overrides`; chạy `npm audit` có allow-list trong CI.

### F19. Certora workflow tải solc không checksum, pip không hash, trong job giữ `CERTORA_KEY`

**Mức độ:** informational. **Confidence: 0.85.**

`certora.yml:32-34` `wget .../solc-static-linux` rồi `mv` vào `/usr/local/bin/solc7.6` không `sha256sum`; `:28` `pip install -r certora/requirements.txt` với `certora-cli==7.29.2` pin version không `--require-hashes`; `:45` `CERTORAKEY: ${{ secrets.CERTORA_KEY }}`; key chỉ in độ dài (`:42`). Không ảnh hưởng artifact on-chain; fork PR không nhận secret. **Khuyến nghị:** verify checksum solc, `pip install --require-hashes`, thêm `permissions: contents: read`.

### F20. `ExtensibleFallbackHandler.onlySelf`: địa chỉ bất kỳ tự đăng ký như một "Safe"

**Mức độ:** informational. **Confidence: 0.75.**

`onlySelf` (`ExtensibleBase.sol:35-41`) chỉ yêu cầu `_msgSender() == _manager()`, tức 20 byte cuối calldata bằng `msg.sender` (`HandlerContext.sol:47-56, 62-64`). Gọi thẳng handler (không qua FallbackManager), bất kỳ địa chỉ X nào thêm địa chỉ của mình vào đuôi calldata sẽ qua check, ghi `safeMethods[X]` (`FallbackHandler.sol:24-26`), `domainVerifiers[X]` (`SignatureVerifierMuxer.sol:79-84`), `safeInterfaces[X]`. Sau đó X gọi `FallbackHandler.fallback` (`:31-41`) với 20 byte đuôi tùy ý, handler bên thứ ba nhận `handle(safe = X, sender = <X chọn>)` với `msg.sender == EFH`. Safe thật không bị ảnh hưởng (mọi mapping key theo `msg.sender`; entry của Safe chỉ ghi được khi Safe là `msg.sender` qua `FallbackManager.sol:70-78`); test tạm của verifier xác nhận entry của victim Safe không đổi. Rủi ro là footgun cho `IFallbackMethod`/`ISafeSignatureVerifier` bên thứ ba tin `msg.sender == EFH` hoặc tin `sender` toàn cục. **Khuyến nghị:** ghi trong NatSpec `IFallbackMethod`/`ISafeSignatureVerifier` rằng `safe` chỉ là `msg.sender` của EFH và có thể là địa chỉ bất kỳ; handler bên thứ ba phải key state theo `safe`.

### F21. Mnemonic mặc định công khai dùng cho live network khi thiếu MNEMONIC/PK

**Mức độ:** informational. **Confidence: 0.8.**

`hardhat.config.ts:69` `DEFAULT_MNEMONIC = "candy maple cake ..."` (Truffle/Ganache, account 0 = `0x6273...`), dùng tại `:77` `mnemonic: MNEMONIC ?? DEFAULT_MNEMONIC` cho mọi live network (mainnet, sepolia, gnosis, zksync, custom). Guard duy nhất `:65-67` chỉ kiểm tra `INFURA_KEY` cho mainnet/sepolia. Địa chỉ CREATE2 không phụ thuộc deployer nên hậu quả là lỗi khó hiểu và mất số tiền operator nạp vào địa chỉ công khai để retry. (Số dòng của finder lệch do commit `418580e` chèn thêm mã trước đó; đã sửa ở trên.) **Khuyến nghị:** throw khi `argv.network !== "hardhat"` mà không có MNEMONIC/PK.

### F22. `local-verify`/`yulcode` chạy solc-js tải từ xa không kiểm tra integrity

**Mức độ:** informational. **Confidence: 0.8.**

`src/utils/solc.ts:13` `solc.loadRemoteVersion(...)`: trong solc-js 0.7.6 đây là `https.get('https://solc-bin.ethereum.org/bin/soljson-<ver>.js')` rồi `requireFromString` không kiểm tra keccak theo `list.json` (khác downloader của Hardhat). Chạy trên máy operator lúc `deploy-contracts` khi `MNEMONIC`/`PK` nằm trong env. Cần compromise origin/CDN hoặc MITM TLS. **Khuyến nghị:** dùng `TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD` của Hardhat hoặc verify theo `list.json` trước khi thực thi.

### F23. Native payment trong `setup()` âm thầm thành 0 khi `tx.gasprice == 0`

**Mức độ:** informational. **Confidence: 0.85.**

`setup()` gọi `handlePayment(payment, 0, 1, paymentToken, paymentReceiver)` với comment `amount = (payment + 0) * 1 = payment` (`Safe.sol:129-133`), nhưng nhánh native (`:252`) nhân với `min(gasPrice=1, tx.gasprice)`: khi `tx.gasprice == 0` (chain zero-fee, private chain, dev node) số tiền là 0, call thành công, setup hoàn tất như đã trả. Nhánh ERC-20 (`:256`) không bị cap. `certora/specs/NativeTokenRefund.spec` có hook `GASPRICE` `require v > 0` cho thấy trường hợp này được biết ở `execTransaction` nhưng không được tài liệu hóa cho `setup`. Chỉ ảnh hưởng `paymentReceiver` bên thứ ba trên chain zero-gas-price; chain EIP-1559 có baseFee > 0. Verifier tái hiện bằng test tạm. **Khuyến nghị:** tài liệu hóa hoặc tách `payNative` không cap cho `setup`; thêm test `initialBaseFeePerGas: 0`.

### F25. NatSpec `SignMessageLib` mô tả đường verify không còn tồn tại

**Mức độ:** informational. **Confidence: 0.9.**

`SignMessageLib.sol:27` nói "Can be verified using EIP-1271 validation method by passing the pre-image of the message hash and empty bytes as the signature". Từ 1.4.0 (`CHANGELOG.md:107-111`) legacy `isValidSignature(bytes,bytes)` đã bị gỡ; entry ERC-1271 duy nhất là `CompatibilityFallbackHandler.isValidSignature(bytes32,bytes)` (`:73-86`) hash `encodeMessageDataForSafe(safe, abi.encode(_dataHash))` (`:76`), nên `signMessage(_data)` chỉ verify on-chain được khi `_data` là đúng 32 byte hash. Fails closed. PoC: `replay-lens.spec.ts`, test "SignMessageLib: only abi.encode(hash)-shaped messages are verifiable through isValidSignature(bytes32)". `SignatureVerifierMuxer.sol:147-153` có cùng cách bọc. **Khuyến nghị:** sửa NatSpec thành `signMessage(abi.encode(hash))` và tham chiếu `getMessageHash`.

### F26. Cấu hình per-Safe của EFH sống trong storage handler dùng chung, không enumerable, tồn tại qua đổi handler/owner

**Mức độ:** informational. **Confidence: 0.75.**

`domainVerifiers` (`SignatureVerifierMuxer.sol:64`), `safeMethods` (`ExtensibleBase.sol:32`), `safeInterfaces` (`ERC165Handler.sol:25`) key theo Safe trong handler singleton. `setFallbackHandler` (`FallbackManager.sol:46-49`) chỉ ghi slot handler, không xóa; chuyển về EFH kích hoạt lại ngay lập tức không có event. Không có hàm enumerate on-chain (khác `getModulesPaginated`). Một domain verifier là oracle ký ERC-1271 cho một domain EIP-712: owner cũ đặt `setDomainVerifier(D_permit2, Evil)`, rotate owner, owner mới audit owners/threshold/modules/guard/handler thấy sạch, owner cũ dùng envelope `0x5fd7e97d || D || ...` (`:121-131`) để rút allowance. Verifier bổ sung: Safe có thể ghi config EFH bằng `execTransaction` tới EFH với địa chỉ mình nối đuôi ngay cả khi EFH chưa là handler đang active, nên state có thể "gieo trước". Người ghi duy nhất là Safe trong threshold (cùng lớp tin cậy với module/guard do owner cũ cài); Ackee 1.5.0 nêu handler phải được tin. **Khuyến nghị:** tài liệu hóa checklist bàn giao (quét event `ChangedDomainVerifier`/`ChangedSafeMethod`), cân nhắc helper `clearConfiguration()` `onlySelf` hoặc cấu trúc enumerable.

### F27. Escape hatch compiler fork-only (scaffolding của chính review)

**Mức độ:** informational. **Confidence: 0.9.**

`hardhat.config.ts:19-40` đăng ký subtask `TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD` khi `AUDIT_LOCAL_SOLC=1` trả `require.resolve("solc/soljson.js")` với `longVersion` cố định, bỏ qua keccak check của Hardhat và tin npm `solc` (lockfile pin `=0.7.6` có integrity). Đã kiểm chứng compiler này tạo bytecode y hệt bản chính thức (rebuild commit v1.5.0 tái tạo 13 địa chỉ CHANGELOG). Commit `418580e` đã harden: từ chối nếu package solc cài không đúng 0.7.6. Giữ ngoài upstream và ngoài môi trường deploy.

### F28. MultiSend / MultiSendCallOnly remap `to == 0` thành `address(this)`

**Mức độ:** informational. **Confidence: 0.85.**

`MultiSend.sol:54`, `MultiSendCallOnly.sol:45` `to := or(to, mul(iszero(to), address()))`: entry `to = 0x0` thành CALL tới chính Safe (`msg.sender == Safe` thỏa `SelfAuthorized.sol:16`), ví dụ `addOwnerWithThreshold`, `enableModule`. Ở 1.3.0/1.4.1 cùng byte nghĩa là CALL tới address zero. Mã có ở cả hai commit được audit 1.5.0 (PR #695, `4cee6ee`), được test ("forwards the call to self when to is zero address"), là thiết kế đã audit; nhưng encoding byte-compatible với library cũ (`MultiSendCallOnly.sol:14-15` quảng cáo tương thích) và CHANGELOG 1.5.0 không ghi. Guard/Roles-style decoder dùng ngữ nghĩa 1.4.1 với rule deny `to != safe` sẽ cho qua entry `to = 0` trong khi on-chain là self-call đặc quyền. Cần quorum owner ký; không có guard trong repo decode MultiSend. **Khuyến nghị:** ghi rõ rule `to == 0 => address(this)` trong CHANGELOG/NatSpec và hướng dẫn cho tác giả guard/decoder.

### G1-1. Enum.Operation ngoài khoảng: 0.7.6 chỉ chặn bằng INVALID (đốt hết gas, không mã lỗi); 0.8 chặn lúc decode

**Mức độ:** informational (finder và verifier đồng ý). **Confidence: 0.9.**

**Mô tả.** Tiền đề "ABI decoder legacy không range-check Enum.Operation" đúng cho decoder (enum decode như uint8, mask 0xff), nên `getTransactionHash` (assembly thuần, `Safe.sol:529`) và `checkSignatures` chấp nhận op=2/255 và chữ ký đúng cho op=2 qua check. Nhưng mọi chỗ dùng enum ở mức Solidity có range check do compiler chèn, chạy `INVALID` (0xfe): `Executor.sol:29` so sánh; ABI-encode enum khi gọi guard (`Safe.sol:175`, `ModuleManager.sol:120`); event SafeL2 (`SafeL2.sol:76, 95`); `abi.encode` trong `CompatibilityFallbackHandler.sol:218`. Op>=2 không bao giờ tới `call`/`delegatecall`, không component nào coi op!=Call là DelegateCall, guard 0.8 cài trên Safe 0.7.6 không bao giờ được gọi với op>=2. Hệ quả quan sát được: INVALID đốt hết gas của frame singleton (PoC: execTransaction op=2 gasLimit 1.000.000, status 0, gasUsed 984.863; bản 0.8.26 chỉ tốn 29.808), revert rỗng không GS code, thứ tự chặn khác theo build (L1: sau nonce++/checkSignatures/GS010 tại `Executor.sol:29`, hoặc `Safe.sol:175` nếu có guard; L2: `SafeL2.sol:76` trước hashing; 0.8: lúc decode với `revert(0,0)` thay vì Panic 0x21). `test/core/Safe.Execution.spec.ts:184-190` pass nhờ INVALID này và chỉ assert `.to.be.reverted`.

**Điều kiện / tác động.** `operation` luôn do owner ký hoặc module tin cậy chọn; người submit tự đốt gas (eth_estimateGas fail trước); nonce không đổi; không bypass. Verifier tái hiện độc lập 3 test (probe 0.7.6/0.8.26, Safe L1/L2 op=2, module path op=2).

**Khuyến nghị.** Tài liệu hóa hành vi (ISafe/IModuleManager/GuardManager chỉ nói "0 CALL, 1 DELEGATECALL"); nếu muốn fail sạch, đọc raw word bằng assembly đầu `execTransaction`/`preModuleExecution` và `revertWithError("GS0xx")` khi `raw > 1`; tăng cường test `:184` để assert revert data rỗng và nonce không đổi.

### G1-2. CI chỉ chạy 0.8.24 qua benchmark happy-path, không chạy test suite

**Mức độ:** finder low, verifier informational; ghi nhận **informational**. **Confidence: 0.8.**

Job `benchmarks` (`.github/workflows/ci.yml:62-84`) là nơi duy nhất dùng 0.8.24 (matrix `:67`, settings optimizer runs 1000000 `:70`) và chỉ chạy `npm run codesize` và `npm run benchmark` (`:84`), tức `hardhat test benchmark/*.ts` (`package.json:27`): sáu spec happy-path, operation 0 (MultiSend op 1 tới singleton MultiSend sau DelegateCallTransactionGuard), `benchmark/utils/setup.ts:89-91` skip case non-CALL. `npm run test` (`package.json:20`) chỉ chạy ở job `tests`/`coverage` với 0.7.6. Hai build khác nhau về failure semantics (G1-1, G1-3) và về optimizer. Verifier đã chạy toàn bộ suite dưới 0.8.24 với đúng settings CI: test:hardhat 464 passing/7 pending, test:L2 467/4, test:L1 1, test:secp256r1 4, không fail; nên hôm nay không có regression 0.8-only, chỉ là CI sẽ không phát hiện nếu có. Mọi deployment production dùng 0.7.6. **Khuyến nghị:** chạy ít nhất `test:hardhat` và `test:L2` trong matrix 0.8.24, hoặc ghi rõ trong README/.env.sample rằng 0.8 chỉ là benchmark-only.

### G1-3. `getTransactionHash` và helper TS chấp nhận mọi uint8 operation; 0.7.6 mask dirty high bits

**Mức độ:** informational. **Confidence: 0.9.**

`Safe.sol:529` `mstore(add(ptr, 128), operation)` sau khi decoder mask uint8 (cảnh báo tại `:496-500`): raw word 0x100/0x101/0x102/(1<<255)|1/0xff01 hash như op 0/1/2/1/1; chữ ký trên op=1 thực thi calldata word 0x101 như DELEGATECALL (event op=1), tức ngữ nghĩa thực thi luôn bằng ngữ nghĩa đã ký. `src/utils/execution.ts:19` (`uint8 operation`) và `buildSafeTransaction` (`:276`) chấp nhận op>=2; `calculateSafeTransactionHash` cho cùng hash với on-chain; `checkSignatures` chấp nhận nhưng không bao giờ thực thi được (G1-1); hash ràng buộc op và nonce không tiêu nên không replay được thành op 0/1. ethers v6 mask 0x101 thành 1 như 0.7.6; decoder strict (eth-abi) và build 0.8 từ chối. Verifier tái hiện 5 test. **Khuyến nghị:** validate `operation ∈ {0,1}` trong helper TS; ghi trong `docs/overview.md:88`/`docs/signatures.md`.

### G2-1. Handler 1.5.0 (CFH/EFH) không verify ERC-1271 trên Safe 1.3.0/1.4.1 dù NatSpec nói tương thích

**Mức độ:** low (verifier impact đồng ý với finder). **Confidence: 0.85.**

**Mô tả.** `CompatibilityFallbackHandler.sol:11` "Provides compatibility between pre 1.3.0 and 1.3.0+ Safe"; `ExtensibleFallbackHandler.sol:12` "Designed to be used with Safe >= 1.3.0". Nhưng đường ERC-1271 gọi `safe.checkSignatures(address(0), messageHash, _signature)` (`CompatibilityFallbackHandler.sol:83`; `SignatureVerifierMuxer.sol:159`, finder ghi 168 là sai), selector `0xf855438b` chỉ có ở Safe 1.5.0 (`Safe.sol:301`). Quét PUSH4 bytecode trong `test/json/safeDeployment.json`: safe130/130l2/141/141l2 chỉ có `0x934f3a11` legacy. Trên Safe cũ, selector lạ quay lại `FallbackManager.fallback` rồi về handler: CFH không có hàm/fallback nên revert rỗng; EFH revert "method handler not set" (`FallbackHandler.sol:33-35`). `setFallbackHandler` (`FallbackManager.sol:46-49`) không kiểm tra version; handler là singleton deterministic; CHANGELOG/overview không ghi version tối thiểu.

**Điều kiện.** Owner của Safe 1.3.0/1.4.1 thực thi `setFallbackHandler(<CFH hoặc EFH 1.5.0>)` mà chưa migrate singleton (flow "update fallback handler" bình thường). Sau đó mọi `isValidSignature(bytes32,bytes)` với chữ ký không rỗng revert rỗng (Permit2, CoW, Seaport, SIWE ngừng hoạt động), và Safe đó làm contract-signer owner của Safe 1.5.0 khác thì ra GS024. Đường `signedMessages` (chữ ký rỗng) và getMessageHash/getModules/simulate/encodeTransactionData/token callback vẫn đúng (không có dữ liệu sai âm thầm). Fails closed, phục hồi bằng khôi phục CFH 1.4.1 hoặc `SafeMigration.migrateSingleton`/`migrateWithFallbackHandler`.

**Bằng chứng.** Verifier chạy test tạm (4 passing, đã xóa): control 1.5.0+CFH150 trả `0x1626ba7e`; safe130/130l2/141/141l2 + CFH150 revert `0x` với chữ ký ECDSA owner hợp lệ; safe141 + EFH150 revert "method handler not set"; 1.4.1 sau `setFallbackHandler(CFH150)` revert rỗng, sau `migrateSingleton` trả magic. `git log -S` xác nhận call 1.5.0-only vào bởi `e9a58ce` (#866).

**Khuyến nghị.** Sửa NatSpec: CFH/EFH 1.5.0 yêu cầu Safe >= 1.5.0 (tương thích ở phía caller; singleton cũ cần migrate trước). Thêm ghi chú "minimum Safe version" trong CHANGELOG và `docs/overview.md`; NatSpec `SafeMigration` nói rõ handler 1.5.0 chỉ đặt sau khi migrate singleton. Tùy chọn: trong `isValidSignature` dùng staticcall và revert với lý do rõ khi revert data rỗng. Thêm regression test cài handler 1.5.0 lên bytecode 1.3.0/1.4.1.

### G2-2. Safe 1.5.0 + CFH 1.5.0 không thể làm contract-signer owner của Safe 1.3.0/1.4.1

**Mức độ:** low (2 verifier/finder đồng ý). **Confidence: 0.85.**

**Mô tả.** Safe 1.3.0/1.4.1 verify contract signature (`v == 0`) bằng legacy `isValidSignature(bytes data, bytes signature)` (selector `0x20c13b0b`) với pre-image. CFH 1.5.0 chỉ có `isValidSignature(bytes32,bytes)` (`CompatibilityFallbackHandler.sol:73`); `CHANGELOG.md:109-111` ghi "legacy function was removed" nhưng không ghi hệ quả: Safe 1.5.0 có CFH 1.5.0 (mọi Safe 1.5.0 mới, hoặc Safe migrate bằng `migrateWithFallbackHandler`, `SafeMigration.sol:80-83`) không thể ký cho parent Safe chưa migrate hay consumer legacy ERC-1271 khác; parent bubble revert rỗng. `migrateSingleton` (`:71-74`) giữ CFH 1.4.1 (có cả hai selector) nên bảo toàn vai trò nested signer. Không bị brick: child gọi `parent.approveHash(txHash)` (là owner) rồi chữ ký `v == 1` thực thi (đã xác nhận).

**Bằng chứng.** Verifier test tạm (7 passing, đã xóa): outer 1.4.1 và outer 1.3.0 với inner 1.5.0+CFH150 -> REVERT(0x) cả hai quy ước hash inner; outer 1.4.1 inner 1.5.0+CFH141 -> OK; outer 1.5.0 inner 1.4.1+CFH141 -> OK; recovery approveHash + v==1 -> OK; probe selector qua fallback Safe xác nhận nguyên nhân ở mức selector. Quét bytecode: CFH 1.5.0 và Safe 1.5.0 không có `0x20c13b0b`, mọi singleton 1.1.1-1.4.1 và CFH 1.4.1 có.

**Khuyến nghị.** Ghi rõ trong CHANGELOG (mục EIP-1271) và `docs/signatures.md`: nâng cấp parent trước child, hoặc dùng `migrateSingleton` cho child cần ký cho parent legacy; mô tả đường phục hồi `approveHash`; thêm nested cross-version case vào migration suite; tùy chọn shim legacy `isValidSignature(bytes,bytes)` trong CFH.

### G2-3. `migrateSingleton` mất `encodeTransactionData`; hai entry point migration bảo toàn hai tập legacy loại trừ nhau; migration test không chạm ERC-1271

**Mức độ:** informational. **Confidence: 0.8.**

1.5.0 gỡ `encodeTransactionData` khỏi core (chỉ còn `getTransactionHash` `Safe.sol:479`), thêm vào CFH 1.5.0 (`:197-228`, `CHANGELOG.md:144`). CFH 1.4.1 không có selector `0xe86637db` (quét bytecode); mọi core 1.1.1-1.4.1 có. `migrateSingleton` giữ handler nên Safe 1.3.0/1.4.1 migrate theo cách này (đường của `test/migration/UpgradeFromSafe130|141.spec.ts`) mất `encodeTransactionData` (revert rỗng) nhưng giữ legacy `isValidSignature(bytes,bytes)` (core 1.5.0 giữ overload compat `checkSignatures(bytes32,bytes,bytes)` `Safe.sol:422`); `migrateWithFallbackHandler` thì ngược lại. NatSpec `SafeMigration.sol:77-78` không nói 1.5.0 là version "requires updating fallback handler". `test/migration/subTests.spec.ts` không gọi `isValidSignature`/`encodeTransactionData`; fixture dùng MockContract làm handler. Hiệu chỉnh của verifier: `checkSignatures`/`checkNSignatures` compat vẫn ở core nên không phụ thuộc handler (finder viết sai); `CHANGELOG.md:136` ("old method was moved ... to the CompatibilityFallbackHandler") cũng lỗi thời so với mã. Verifier tái hiện 3 test. **Khuyến nghị:** ghi rõ trong CHANGELOG/NatSpec tập legacy mỗi entry point giữ; mở rộng migration test với handler thật.

### G3-1. Owner secp256r1 làm liveness Safe phụ thuộc precompile 0x100; Safe đa chain counterfactual có thể bị khóa

**Mức độ:** finder low, verifier informational (0.65); ghi nhận **informational**. **Confidence: 0.65.**

`OwnerManager.requireIsValidOwner` (`:118-122`) chỉ từ chối 0, SENTINEL, chính Safe; địa chỉ P-256 (`keccak256(qx||qy)[12:]`, `Safe.sol:393`) được chấp nhận trên mọi chain. Owner đó chỉ ký được qua nhánh `v == 2` gọi `p256Verify` (`EIP7951.sol:39-44`), trả false khi 0x100 không trả đúng 32 byte bằng 1, rồi GS028 (`Safe.sol:396`). `v == 1` cần `msg.sender == owner`/`approveHash` (GS030), `v == 0` cần code (GS024), ecrecover không thể cho ra địa chỉ đó. Owner management là `authorized` (GS031). Safe mà threshold chỉ đạt được qua owner P-256 và không có module sẽ bất động trên chain không có 0x100 (không swap owner, không hạ threshold được). `createProxyWithNonce` salt chỉ từ `keccak256(initializer)` + saltNonce (`SafeProxyFactory.sol:89`) và `SafeToL2Setup` (`:7-9`) tồn tại để cùng địa chỉ trên mọi chain, nên tài sản gửi tới địa chỉ counterfactual trên chain thiếu precompile bị đóng băng cho tới khi chain ship RIP-7212/EIP-7951. Đây là vấn đề liveness thuần túy: không ai dùng được slot owner đó để lấy tiền. Tài liệu: `IOwnerManager.sol:30-36, 58-64` có cảnh báo lock-out cho self-owner n/n nhưng không có cho P-256; CHANGELOG không có mục secp256r1; chỉ `docs/error_codes.md:53-55` nhắc. Verifier test tạm: 1-of-1 P-256 Safe, không precompile -> `execTransaction(swapOwner)` GS028, `approveHash` GS030; có precompile -> swap thành công. Verifier hạ xuống informational vì hành vi đúng thiết kế EIP-7951, đã có test `Safe.Signatures.spec.ts:541-578` cho GS028 khi không có precompile, cùng lớp với owner ERC-1271 chưa deploy ở chain khác, không có mitigation on-chain khả thi. **Khuyến nghị:** thêm cảnh báo NatSpec tại `addOwnerWithThreshold`/`swapOwner`/`setup`/`docs/overview.md` về yêu cầu precompile và counterfactual deployment; thêm CHANGELOG cho #1061 ghi rằng precompile vắng mặt và chữ ký sai đều ra GS028.

## 8. Findings còn tranh cãi

### F05. Cờ `ReentrancyTransactionGuard` toàn cục per deployment; NatSpec `:26` sai

Phiếu: refute không thật (0.88, informational), impact thật (0.85, informational). Cơ chế đúng: một slot hằng (`:12`) dùng chung cho đường tx (`:57-59`) và đường module (`:87-89`), không key theo Safe; Safe A gọi `B.execTransaction` lồng nhau trên cùng instance bị "Reentrancy detected" (PoC test "a shared guard deployment blocks legitimate nested Safe-calls-Safe execution" pass). Lý do chưa chắc là finding: `CHANGELOG.md:691` đã tài liệu hóa đúng hành vi này ("does not differentiate between different Safes ... prevents reentrancy in all of the connected Safes"), `:687` đánh dấu non-production; unit test deploy instance riêng mỗi Safe. Impact lens thêm: T_A chỉ revert toàn bộ khi `safeTxGas==0 && gasPrice==0`, ngược lại nonce của A bị đốt với `ExecutionFailure`. Phần còn lại không bị tranh cãi: NatSpec `:26` ("unique to the contract instance and the function in which it is called") sai vì hai hàm dùng chung slot. Cùng fix với F01 (key theo `msg.sender`). **Confidence 0.6** rằng đây là vấn đề cần xử lý ngoài việc sửa NatSpec.

### F08. Không có guard bắt buộc compiler settings chuẩn khi deploy live; `local-verify` tự tham chiếu

Phiếu: refute không thật (0.75, informational), impact thật (0.7, low). Cơ chế đúng: `soliditySettings = JSON.parse(SOLIDITY_SETTINGS)` (`hardhat.config.ts:80`) rơi vào entry 0.7.6 đầu tiên (`:109-111`), Hardhat chọn entry đầu khớp nên entry chuẩn là dead; hardhat-deploy compile trước deploy; `local-verify` recompile từ metadata của chính deployment (`local_verify.ts:9, 27`) nên build optimized ở địa chỉ không chuẩn vẫn SUCCESS; không script nào so địa chỉ với CHANGELOG. Lý do chưa chắc: kịch bản coverage của finder không xảy ra được vì settings viaIR trong `.env.sample` làm solc 0.7.6 InternalCompilerError (cả hai verifier xác nhận); biến thể optimizer-only compile được và dời địa chỉ CREATE2, nhưng `SOLIDITY_SETTINGS` là knob có chủ đích, README và bảng địa chỉ CHANGELOG là kiểm soát thủ công, CREATE2 bảo đảm bộ chuẩn không thể bị "đầu độc". Fix rẻ: từ chối deploy live khi `SOLIDITY_VERSION`/`SOLIDITY_SETTINGS` được đặt, và so địa chỉ với bảng kỳ vọng. **Confidence 0.55** rằng đây là finding ở mức low.

## 9. Giả thuyết đã kiểm tra và loại bỏ

Tóm tắt theo vùng (chi tiết đầy đủ trong `finders.json` ở scratchpad). Mọi mục dưới đây đều có đối chiếu mã, nhiều mục có PoC trong `replay-lens.spec.ts`, `post-audit-erc1271-strict-return.spec.ts` hoặc test tạm.

**Chữ ký và checkNSignatures (core-sig, cross-cutting-replay, assembly-memory).** Out-of-bounds trong buffer packed: GS020/GS021/GS022/GS023/GS027 với SafeMath giữ mọi đọc trong bound. Aliasing con trỏ động với phần tĩnh chưa xử lý: không giảm threshold, mỗi owner tự validate byte của mình. `ecrecover` trả 0: chặn bởi `currentOwner <= lastOwner` (lastOwner khởi tạo 0) và `owners[0]==0`; v ∈ {3..26, 29, 30, >=33} đều ra GS026 (PoC). Owner trùng với kiểu chữ ký lẫn lộn: so owner đã resolve, thứ tự tăng nghiêm ngặt. `v=1` với executor giả: handler/muxer truyền executor `address(0)`; r=0 và r=SENTINEL đều bị chặn (PoC "v=1 with r=0 via the handler (executor=0) is rejected ... (GS026)", "executor shortcut ... requires msg.sender to be an owner"). secp256r1: owner = keccak(qx||qy) không giả mạo được; `signerAddress` dirty bits được compiler clean khi so sánh; input đúng 160 byte; malleability đã tài liệu (`Safe.sol:359-360`). approvedHashes tồn tại vĩnh viễn (tài liệu `ISafe.sol:147`), hồi sinh khi re-add owner (PoC). Nested mutual ownership A<->B: đệ quy bị giới hạn bởi byte chữ ký, kết thúc ở GS024 (PoC 3 tầng). Precompile 0x02/0x04 làm owner: thêm được nhưng không qua được contract-signature check (PoC). Tx-hash và SafeMessage-hash không hoán đổi được (PoC). Cross-chain replay: domainSeparator dùng `chainid()`/`address()` live. Legacy overloads `checkSignatures(bytes32,bytes,bytes)`: dùng `msg.sender` làm executor với cảnh báo rõ ở `Safe.sol:416, 432`; CFH 1.4.1 trên Safe 1.5.0 không cho non-owner shortcut (GS026/GS025, đã test trong gap 2). `getTransactionHash` assembly: struct hash tính trước khi ghi đè, `0x1901` đặt đúng, khớp tham chiếu TS 100 case ngẫu nhiên.

**Gas và refund (gas-refund).** `gasleft() - 2500` underflow: GS010 bảo đảm >= 3000 gas; nếu vẫn underflow thì EIP-150 cap về "all gas", không có state khai thác được. Wrap-around của `(safeTxGas << 6)` và `safeTxGas + 2500`: không giá trị uint256 nào làm cả hai nhỏ cùng lúc. `gasUsed.sub(gasleft())` không revert; refund bị chặn bởi tham số đã ký. Reentrancy lúc refund (`Safe.sol:253` full-gas call, ERC-777 gasToken, 7702 tx.origin): nonce đã tăng, không storage nào ghi sau refund; chỉ ảnh hưởng thứ tự event/hook, đã có test. `transferToken` return-data: returndatasize 0 -> success, 32 -> word != 0, khác -> GS012; gasToken không có code bị bỏ qua là hành vi NatSpec. Revert bubbling `:207-216` đúng. `safeTxGas == 0 && gasPrice > 0` cho inner call 0 gas: hành vi 1.3.0 có tài liệu. DELEGATECALL bỏ qua `value`: vấn đề UX, không có đường tấn công. `tx.gasprice == 0` ở `execTransaction`: tiền điều kiện của Certora spec (chỉ `setup` được báo cáo, F23). #1115/#1123 không tương tác với gas accounting.

**Owner/Module/Guard/Fallback manager (managers).** Linked list owner: insert/remove/swap giữ bất biến, `ownerCount` không desync, threshold math đúng (73 test pass). Re-init qua `threshold == 0`: chỉ reachable qua raw storage write bởi bên tin cậy hoặc EIP-7702 (F02). `authorized` reachability: fallback handler/guard được CALL nên callback có `msg.sender` là handler/guard, fail GS031 (PoC handler bounce 3-byte calldata: owner không đổi). Safe tự làm module: `enableModule(safe)` cho phép `execTransaction(to=self, execTransactionFromModule(..., DelegateCall))` nhưng cùng signer đã có thể bật module bất kỳ; module nằm ngoài tx guard theo thiết kế. Pagination module: `moduleCount-1` underflow chỉ ở account chưa init (revert). `execTransactionFromModuleReturnData` assembly: FMP bump đúng, returndata không bị clobber. Guard hook: guard cache trước thực thi (`Safe.sol:172`), test "is called when removed". `setGuard(self)`: GS300 với handler shipped. Storage slot: ba hằng keccak khớp preimage, không trùng ERC-1967, layout slot 0-8 khớp `SafeStorage.sol`. FallbackManager: GS400 chặn handler==self; vector selector 3 byte không reach được hàm `authorized` ở 1.5.0 (PoC). `simulateAndRevert` luôn revert. EIP-7702 EOA gửi tx tới chính mình bypass chữ ký/guard cho hàm `authorized`: vốn có của EIP-7702.

**Proxy, setup, migration (proxy-setup-migration).** `SafeProxy.masterCopy()` short-circuit: `shl(96, sload(0))` bỏ dirty bits, encoding đúng (test). Factory: salt gồm keccak(initializer) nên front-run chỉ deploy đúng Safe nạn nhân muốn; initializer fail revert cả CREATE2; `createProxyWithCallback` đã gỡ từ 1.4.0. `setup` ordering: threshold đặt trước fallback handler/modules nên re-enter setup fail GS200. `paymentReceiver == 0 -> tx.origin`: thiết kế relayer. `isThisDelegatedAccount`: EXTCODECOPY đọc đúng designator `0xef0100`, proxy/contract không bao giờ bắt đầu bằng byte này. Storage layout giống 1.0.0-1.4.1 (migration test từ 1.1.1/1.2.0/1.3.0/1.4.1 pass). `SafeMigration`: onlyDelegateCall qua immutable; không version check nhưng mọi version hỗ trợ cùng layout. `SafeToL2Setup`: onlyDelegateCall + onlyNonceZero + onlyContract; chọn l2Singleton được commit trong CREATE2. `Migrate_1_3_0_to_1_2_0`: ví dụ, cần owner. Singleton tự dùng: threshold=1, không owner, không gọi được.

**Handlers (handlers).** `_msgSender()` spoof trên Safe >= 1.3.0: FallbackManager luôn nối `caller()` sau toàn bộ calldata nên 20 byte cuối là caller thật. `onlyFallback` "trick": tài liệu hóa và có test. Message/tx hash collision: typehash khác, domain ràng buộc chain+Safe. `simulate()` #1123: `response` layout `[len][data]`, revert đúng `len` byte; L giả từ caller ngoài Safe chỉ gây OOB/OOG trong frame của chính caller; test BadSimulator mode 0-3. Calldata 1-3 byte qua Safe: chỉ dispatch được hàm không tham số (`getModules()`), không hàm state-changing nào (PoC). `SignatureVerifierMuxer`: verifier chỉ dùng khi `keccak(0x1901||D||keccak(typeHash||encodeData)) == _hash` (test forge domain). `IStaticFallbackMethod.handle` là view nên STATICCALL. `MarshalLib` dirty bits: mask 160 bit, isStatic từ byte đỉnh. ERC165Handler: 0xffffffff không set được. Token callback trả selector vô điều kiện: chỉ làm Safe nhận token. Không delegatecall/selfdestruct trong handler. Reentrancy qua custom handler/verifier: `msg.sender` là handler, không có quyền Safe.

**Libraries và accessor (libraries).** MultiSend `onlyDelegateCall` qua immutable `MULTISEND_SINGLETON` (test + PoC). Thực thi rác do đọc OOB: không, memory sau array là 0 (PoC). Cursor wrap/infinite loop: OOG trước (PoC). MultiSendCallOnly gọi trực tiếp với msg.value: không state, tài liệu `CHANGELOG.md:703`. `CreateCall`: `require(newContract != 0)`, event từ Safe khi delegatecall; revert reason initcode bị nuốt (Certora I-03 đã nêu). `SignMessageLib` gọi trực tiếp: `domainSeparator()` không có trên singleton nên revert trước sstore; slot 7 khớp `Safe.sol:87`. `SimulateTxAccessor`: chỉ qua `simulateAndRevert`; return-data assembly bump FMP đúng. `getStorageAt` `length << 5` wrap: view, OOG (PoC "getStorageAt with a length that overflows ... reverts"). Không library nào giữ state ngoài SignMessageLib (chỉ ghi được qua delegatecall).

**Guards (guards).** Cờ Reentrancy kẹt sau revert/fail: revert ngoài rollback sstore, fail trong vẫn tới `checkAfterExecution`. Guard không có code pass âm thầm: không, `setGuard(EOA)` revert và guard mất code làm `Safe.sol:175` revert (DoS đã tài liệu `IGuardManager.sol:20-22`). Guard check sau nonce++: revert guard rollback nonce; checkSignatures chỉ staticcall nên không đổi guard trước `:172`. `msgSender`/`signatures` thừa byte truyền vào guard: không guard in-scope tin mù. `OnlyOwnersGuard` bị lừa: guard gọi từ Safe trực tiếp, `isOwner` không qua handler, Safe không tự là owner (GS203). `DelegateCallTransactionGuard` bypass qua MultiSend: lý do `MultiSendCallOnly` tồn tại (header `:6-7`). Module guard ordering/hash plumbing đúng. `safe.nonce() - 1` underflow: nonce >= 1 khi guard chạy.

**Assembly/memory (assembly-memory).** Mọi block assembly dưới `contracts/` (trừ test) được đọc: `ErrorMessage.revertWithError` layout Error(string) đúng (0x64 byte); `EIP7951.p256Verify` không tin stale memory; `EIP7702` đọc 3 byte; `HandlerContext._msgSender` clean; `SignatureDecoder.signatureSplit` đọc trong bound; `SecuredSignatureValidator` short-circuit `&&` nên `abi.decode` không thấy <32 byte; không precompile nào (0x01-0x11, 0x100) trả đúng magic 32 byte left-aligned cho input `abi.encodeWithSelector` 100+32k byte; 0.8.x/viaIR: mọi block (trừ SafeProxy, luôn halt) là memory-safe.

**DevOps/supply chain (devops-supplychain).** Địa chỉ HEAD khác CHANGELOG là do mọi file contract đổi sau tag (kể cả comment làm đổi metadata hash); rebuild commit v1.5.0 tái tạo đúng 13 địa chỉ. Salt/factory/constructor-arg trong `src/deploy` đúng; chain lạ throw thay vì fallback Arachnid. `ensureCreate2DeployerReady` no-op trên chain có factory. `pull_request_target`/script injection: không có. Secrets committed: không (`.env` gitignored). npm scripts: không postinstall/curl|sh. `certora/Makefile clean`: scoped cwd. `.husky/pre-commit` bypass không hoạt động nhưng fail safe.

**Post-audit diff (post-audit-diff).** #1115: byte layout magic đúng (bytes4->bytes32 left-aligned); Safe lồng nhau >= 1.3.0 trả đúng 32 byte (PoC "a Safe (CompatibilityFallbackHandler) as ERC-1271 owner still validates"); nuốt revert không tạo ra `true` (PoC nonce không tiêu, gas-burner ra GS024); return-bomb không có amplification; `view` đã là STATICCALL từ trước; bỏ EXTCODESIZE check chỉ đổi lỗi rỗng thành GS024; ABI/storage không đổi; EIP-170 còn dư (Safe 20.869 B, SafeL2 21.649 B). #1123: đúng, test byte-exact pass; không instance nào của pattern này ở nơi khác (quét mọi `returndatacopy`/`revert`). SafeMath.sub, dời slot constant, domainSeparator assembly: behaviour-preserving.

**Critic và gap round.** Selector collision toàn bộ dispatch chain: không có. ERC-165 misreporting: không. Token callback làm phishing: không có hiệu ứng state. ERC-4337: chỉ test module "DO NOT USE". zkSync/EraVM remnants: không. Gas-limit DoS trong getter: `getOwners` O(n) view, không consumer on-chain. Event parity Safe/SafeL2: đúng. Chuỗi `revertWithError` đều 5 byte. Gap 3: không chain nào host precompile khác tại 0x100 được xác định; return convention cũ (32-byte zero), over-long, revert đều ra GS028 (mock); gas 3450/6900/12000 chỉ ảnh hưởng estimation; RPC công khai bị proxy chặn nên không probe được on-chain.

## 10. Nhận xét về các thay đổi sau audit 1.5.0

**#1115 `SecuredSignatureValidator` (commit `77901a5`).** Cài đặt đúng và nghiêm ngặt hơn mã cũ: `owner.staticcall(data)` rồi `success && result.length == 32 && abi.decode(result,(bytes32)) == bytes32(EIP1271_MAGIC_VALUE)` (`SecuredSignatureValidator.sol:22-23`). PoC xác nhận: chấp nhận đúng `0x1626ba7e || 28 byte 0`; từ chối 33/64 byte, 31/4/0 byte, dirty low bits, magic lệch phải, EOA, precompile, validator revert/OOG, luôn với GS024 và revert toàn phần (nonce không tiêu). So với caller high-level legacy cùng solc 0.7.6, mã cũ chấp nhận 33/64 byte và dirty low bits, đúng như CHANGELOG mô tả breaking change. Không tìm thấy đường nào biến revert bị nuốt thành chấp nhận sai. Điểm yếu còn lại là quy trình: (a) chỉ có test cho trường hợp revert (F14), (b) `docs/error_codes.md` GS024 chưa cập nhật (F17), (c) Certora `Signatures.spec:16` summarize `checkContractSignature` là NONDET nên đường mới nằm ngoài formal verification chạy trong CI, (d) overflow path SafeMath ra revert rỗng thay vì GS (F15, có trước #1115). Mục tiêu "không để byte chữ ký điều khiển revert data" của PR đạt được.

**#1123 `CompatibilityFallbackHandler.simulate` (commit `f8fc2f2`).** `revert(add(response, 0x20), mload(response))` (`:175`) đúng: `response` có layout `[len][data]` copy từ `returndata[0x20:]`, nên ném lại đúng `len` byte (trước đây dư 32 byte đuôi, chỉ là rác với decoder Error(string)). Guard `or(success, lt(returndatasize(), 0x40))` bảo vệ caller ngoài Safe; `len` giả chỉ gây OOB/OOG trong frame của chính caller (tài liệu "only for Safes"). Test "should propagate exact revert data" pass; không có cùng pattern lỗi ở điểm revert/return nào khác (`Safe.sol:212-213`, `SafeProxy.sol:72-76`, `SafeProxyFactory.sol:72-73`, `MultiSend*.sol`, `FallbackManager.sol:80-84`, `StorageAccessible.sol:43-45`, `SimulateTxAccessor.sol:61-65`, `ModuleManager.sol:197-201`). Không có tương tác với gas accounting hay guard.

**Các commit sau audit khác (#998, #1062, #1061, #1019).** Đây mới là vùng rủi ro quy trình lớn hơn: thêm kiểu chữ ký core mới (`v == 2`), logic self-ownership EIP-7702, helper codehash, mà không có audit, CHANGELOG hay spec chữ ký đi kèm (F13, F09, G3-1), đồng thời tạo ra regression F04 và hazard F02. Về mặt mã, review không tìm thấy lỗ hổng khai thác được trong chúng; `p256Verify` cũng bị Certora summarize là CONSTANT nên không được formal verification phủ.

## 11. Khuyến nghị quy trình

1. **Tests.** Port các case của `post-audit-erc1271-strict-return.spec.ts` vào `test/core/Safe.Signatures.spec.ts` và suite CFH (F14). Thêm boundary test GS010 với `to` cold (F07). Tăng cường `Safe.Execution.spec.ts:184` để assert revert data rỗng và nonce không đổi (G1-1). Thêm migration test: Safe <=1.2.0 có self-owner (F04); handler 1.5.0 trên bytecode 1.3.0/1.4.1 (G2-1); nested cross-version Safe (G2-2); post-migration `isValidSignature`/`encodeTransactionData` với handler thật thay MockContract (G2-3). Thêm test `gasPrice: 0` cho `setup` payment (F23). Thêm hai-entry case cho MultiSend op>=2 (F10). Mock 0x100 cho các return convention (G3-2, dù bị bác bỏ là defect, vẫn là coverage hữu ích). Cân nhắc giữ các PoC trong `docs/security-review/poc/` làm regression test (tag `@skip-on-coverage` đã có cho ba file).
2. **CI.** Chạy `test:hardhat`/`test:L2` trong matrix 0.8.24 hoặc ghi rõ 0.8 là benchmark-only (G1-2). Thêm `permissions: contents: read`, pin SHA (F16). Checksum solc và `pip --require-hashes` trong `certora.yml` (F19). `npm audit` với allow-list (F18). Coverage job hiện bỏ qua case `@secp256r1` (chỉ chạy trong job tests).
3. **Deployment.** `local-verify` phải fail pipeline khi FAILURE và chạy sau upload như README (F06). Từ chối live network khi thiếu MNEMONIC/PK (F21) hoặc khi `SOLIDITY_VERSION`/`SOLIDITY_SETTINGS` được đặt, và so địa chỉ CREATE2 với bảng kỳ vọng (F08). Dùng compiler đã verify của Hardhat cho `local-verify` (F22). Không mang escape hatch `AUDIT_LOCAL_SOLC` lên upstream hay môi trường deploy (F27).
4. **Tài liệu và audit.** Bổ sung CHANGELOG "Current version" cho #998/#1062/#1061/#1019 và ghi rõ `docs/audit_1_5_0.md` không phủ chúng, hoặc tiến hành audit bổ sung trước release kế tiếp (F13). Thêm mục secp256r1 vào `docs/signatures.md` (F09), cập nhật GS024/GS027 (F17), cảnh báo precompile cho owner P-256 (G3-1), hướng dẫn EIP-7702 với tham chiếu `safe-eip7702` proxy (F02), version tối thiểu cho handler 1.5.0 và tập legacy từng entry point migration (G2-1/G2-2/G2-3), rule `to == 0` của MultiSend (F28), checklist bàn giao Safe dùng EFH (F26), sửa NatSpec `SignMessageLib` (F25) và `ReentrancyTransactionGuard:26` (F05). Mở rộng Certora spec để `checkContractSignature`/`p256Verify` không bị summarize khỏi scope.
5. **Mã ví dụ.** Sửa ba guard ví dụ (F01/F03/F05/F12) bằng cách key state theo `msg.sender`, hoặc đánh dấu rõ ngay trong header contract rằng không deploy nguyên bản được.

## 12. Caveats và giới hạn của review

- **Không truy cập được chain thật.** RPC công khai bị proxy chặn, không cài safe-deployments, nên không xác định được singleton 1.5.0 đã deploy (`0xFf51A5898e...`) có chứa `v == 2`/EIP-7702 hay không, và không probe được precompile 0x100 trên các chain thực tế (G3-1 dựa trên spec và mock).
- **Repo là shallow clone.** Hai commit audit chỉ tồn tại như object cô lập; "after-set" được suy từ content diff `git diff 5d26505 HEAD -- contracts/` và ngày commit, không từ ancestry.
- **Build 0.8.24 không tải được trong sandbox** (binaries.soliditylang.org 403); verifier dùng solc-js 0.8.24 từ npm (G1-2) và 0.8.26 cho probe (G1-1); enum decode validation giống nhau trên 0.8.x nên kết luận giữ nguyên.
- **Không formal verification mới.** Certora không được chạy lại; nhận xét về spec dựa trên đọc `certora/specs/*.spec`.
- **`contracts/examples/*` là mã tham khảo.** Các finding low ở đây (F01, F03) chỉ thành vấn đề thực tế khi integrator deploy nguyên bản; brief loại các issue chỉ trong `contracts/test/**` nên không được báo cáo.
- **Giới hạn vốn có của review một lần.** Nhiều lens kết luận "không tìm thấy" sau khi kiểm tra có hệ thống, nhưng không chứng minh được tính không tồn tại; ví dụ không khảo sát hành vi `CreateCall` trên zkSync Era (zksolc) hay tương tác của library với EOA 7702 ở mức sâu hơn những gì đã ghi.
- **Số dòng.** Các tham chiếu `hardhat.config.ts` bị lệch do commit scaffolding `418580e` chèn mã; `SignatureVerifierMuxer.sol:168` trong finder đúng là `:159`. Các tham chiếu trong báo cáo này đã được kiểm tra lại tại HEAD `418580e` (mã contract không đổi so với `f8fc2f2`).
- **Confidence tổng thể 0.8.** Phần chắc chắn nhất là việc không có lỗi critical/high trong core và tính đúng của #1115/#1123 (nhiều lens và PoC hội tụ). Phần kém chắc hơn là mức độ nghiêm trọng của F02 (chia phiếu, phụ thuộc vào việc xem đây là hazard tích hợp hay defect) và G3-1 (phụ thuộc hiện trạng precompile trên từng chain mà review không quan sát được).

## 13. Phụ lục: dữ liệu thô của review

- `data/findings.json`: 28 finding sau dedup (F01..F28) với mô tả, đường tấn công, bằng chứng, khuyến nghị của finder.
- `data/votes.jsonl`: toàn bộ verdict của verifier (mỗi dòng một phiếu: id, lens, real, severity, confidence, reasoning, preconditions, exploit_sketch, test_ran), gồm cả 10 phiếu tự xác minh của orchestrator cho nhóm tài liệu/CI/tooling.
- `data/finders.json`: ghi chú "reviewed" và "ruled_out" của 11 finder, là nguồn cho mục 9.
- `data/gap-round.json`: 4 gap do critic đề xuất, 8 finding của 3 gap finder và verdict tương ứng.
- Scaffolding chỉ dùng cho review: `hardhat.config.ts` có escape hatch `AUDIT_LOCAL_SOLC=1` (inert nếu không đặt biến), file `.env` local (không commit) đặt biến này để test chạy được trong sandbox không tải được solc.
