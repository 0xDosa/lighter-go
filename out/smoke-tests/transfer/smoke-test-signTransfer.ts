import { SignerWASM } from "../../signer";
import {
  ACCOUNT_INDEX,
  API_KEY_INDEX,
  CHAIN_ID,
  SEED_PHRASE,
  URL,
} from "../base";

console.log("🧪 Testing signTransfer with fee and memo...");

const signer = SignerWASM.getInstance();

async function runTest() {
  try {
    // 1. Prerequisites
    await signer.waitForReady();
    const apiKey = await signer.generateAPIKey(SEED_PHRASE);
    if (!apiKey.privateKey) {
      throw new Error("Failed to generate private key for the test.");
    }
    await signer.createClient(
      URL,
      apiKey.privateKey,
      CHAIN_ID,
      API_KEY_INDEX,
      ACCOUNT_INDEX
    );
    console.log("🛠️ Client created for test.");

    // 2. Test signTransfer with valid parameters
    console.log("\n📋 Testing signTransfer with valid parameters...");
    
    const transferParams = {
      toAccountIndex: ACCOUNT_INDEX + 1, // Transfer to a different account
      usdcAmount: 1000000, // 1 USDC (6 decimals)
      fee: 1000, // 0.001 USDC fee
      memo: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 hex characters (32 bytes)
      nonce: 201
    };
    
    console.log("📝 Transfer Params:", JSON.stringify(transferParams, null, 2));

    const signedTransfer = await signer.signTransfer(
      transferParams.toAccountIndex,
      transferParams.usdcAmount,
      transferParams.fee,
      transferParams.memo,
      transferParams.nonce
    );
    
    if (!signedTransfer || !signedTransfer.Nonce) {
      throw new Error("Transfer signing failed.");
    }
    
    console.log("✅ Transfer signed successfully.");
    console.log("📄 Signed Transfer Tx:", JSON.stringify(signedTransfer, null, 2));

    // 3. Verify the transfer structure
    console.log("\n🔍 Verifying transfer structure:");
    console.log(`FromAccountIndex: ${signedTransfer.FromAccountIndex} (should be ${ACCOUNT_INDEX})`);
    console.log(`ToAccountIndex: ${signedTransfer.ToAccountIndex} (should be ${transferParams.toAccountIndex})`);
    console.log(`ApiKeyIndex: ${signedTransfer.ApiKeyIndex} (should be ${API_KEY_INDEX})`);
    console.log(`USDCAmount: ${signedTransfer.USDCAmount} (should be ${transferParams.usdcAmount})`);
    console.log(`Fee: ${signedTransfer.Fee} (should be ${transferParams.fee})`);
    const displayMemoHex = Array.isArray(signedTransfer.Memo) 
      ? signedTransfer.Memo.map(b => b.toString(16).padStart(2, '0')).join('')
      : signedTransfer.Memo;
    console.log(`Memo: ${displayMemoHex} (should be ${transferParams.memo})`);
    console.log(`Nonce: ${signedTransfer.Nonce} (should be ${transferParams.nonce})`);
    console.log(`Has MessageToSign: ${!!signedTransfer.MessageToSign}`);
    console.log(`Has Signature: ${!!signedTransfer.Sig}`);

    // 4. Verify required fields
    if (signedTransfer.FromAccountIndex !== ACCOUNT_INDEX) {
      throw new Error(`FromAccountIndex mismatch: expected ${ACCOUNT_INDEX}, got ${signedTransfer.FromAccountIndex}`);
    }
    if (signedTransfer.ToAccountIndex !== transferParams.toAccountIndex) {
      throw new Error(`ToAccountIndex mismatch: expected ${transferParams.toAccountIndex}, got ${signedTransfer.ToAccountIndex}`);
    }
    if (signedTransfer.USDCAmount !== transferParams.usdcAmount) {
      throw new Error(`USDCAmount mismatch: expected ${transferParams.usdcAmount}, got ${signedTransfer.USDCAmount}`);
    }
    if (signedTransfer.Fee !== transferParams.fee) {
      throw new Error(`Fee mismatch: expected ${transferParams.fee}, got ${signedTransfer.Fee}`);
    }
    // Convert memo byte array back to hex string for comparison
    const memoBytes = Array.isArray(signedTransfer.Memo) ? signedTransfer.Memo : [];
    const memoHex = memoBytes.map(b => b.toString(16).padStart(2, '0')).join('');
    if (memoHex !== transferParams.memo) {
      throw new Error(`Memo mismatch: expected ${transferParams.memo}, got ${memoHex} (from bytes: ${signedTransfer.Memo})`);
    }
    if (!signedTransfer.MessageToSign) {
      throw new Error("MessageToSign field is missing - L1 signature support not working");
    }
    if (!signedTransfer.Sig) {
      throw new Error("Signature field is missing");
    }

    // 5. Test transfer with different memo (exact 32 bytes)
    console.log("\n📋 Testing transfer with different memo...");
    const transferParams2 = {
      toAccountIndex: ACCOUNT_INDEX + 2,
      usdcAmount: 2000000, // 2 USDC
      fee: 2000, // 0.002 USDC fee
      memo: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // 64 hex characters (32 bytes)
      nonce: 202
    };

    const signedTransfer2 = await signer.signTransfer(
      transferParams2.toAccountIndex,
      transferParams2.usdcAmount,
      transferParams2.fee,
      transferParams2.memo,
      transferParams2.nonce
    );

    if (!signedTransfer2 || signedTransfer2.Nonce !== transferParams2.nonce) {
      throw new Error("Second transfer signing failed.");
    }
    console.log("✅ Second transfer signed successfully.");

    // 6. Test transfer with empty memo
    console.log("\n📋 Testing transfer with empty memo...");
    const transferParams3 = {
      toAccountIndex: ACCOUNT_INDEX + 3,
      usdcAmount: 3000000, // 3 USDC
      fee: 3000, // 0.003 USDC fee
      memo: "", // Empty memo
      nonce: 203
    };

    const signedTransfer3 = await signer.signTransfer(
      transferParams3.toAccountIndex,
      transferParams3.usdcAmount,
      transferParams3.fee,
      transferParams3.memo,
      transferParams3.nonce
    );

    if (!signedTransfer3 || signedTransfer3.Nonce !== transferParams3.nonce) {
      throw new Error("Third transfer signing failed.");
    }
    console.log("✅ Third transfer with empty memo signed successfully.");
    
    // Verify empty memo results in all zeros
    const memoBytes3 = Array.isArray(signedTransfer3.Memo) ? signedTransfer3.Memo : [];
    const allZeros = memoBytes3.every(b => b === 0);
    if (!allZeros) {
      throw new Error("Empty memo should result in all zero bytes");
    }
    console.log("✅ Empty memo correctly resulted in zero bytes");

    // 7. Test error case: invalid memo length
    console.log("\n📋 Testing error case: invalid memo length...");
    try {
      await signer.signTransfer(
        ACCOUNT_INDEX + 3,
        1000000,
        1000,
        "short", // Invalid: too short (should be 64 hex chars)
        203
      );
      throw new Error("Should have failed with invalid memo length");
    } catch (error) {
      if (error instanceof Error && error.message.includes("memo expected to be 64 hex characters")) {
        console.log("✅ Correctly rejected invalid memo length");
      } else {
        throw error;
      }
    }

    console.log("\n🎉 All transfer tests passed successfully!");

  } catch (error) {
    console.log("\n❌ FAILED: Smoke detected!");
    console.error("💥 Error:", error);
    process.exit(1);
  }
}

runTest();
