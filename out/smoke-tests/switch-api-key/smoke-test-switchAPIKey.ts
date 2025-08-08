import { SignerWASM } from "../../signer";
import {
  ACCOUNT_INDEX,
  API_KEY_INDEX,
  CHAIN_ID,
  SEED_PHRASE,
  SEED_PHRASE_2,
  URL,
} from "../base";

console.log("🧪 Testing switchAPIKey functionality...");

const signer = SignerWASM.getInstance();

async function runTest() {
  try {
    // 1. Prerequisites
    await signer.waitForReady();
    
    // Generate two different API keys
    const apiKey1 = await signer.generateAPIKey(SEED_PHRASE);
    const apiKey2 = await signer.generateAPIKey(SEED_PHRASE_2);
    
    if (!apiKey1.privateKey || !apiKey2.privateKey) {
      throw new Error("Failed to generate private keys for the test.");
    }
    
    console.log("🛠️ Generated two API keys for testing.");
    console.log(`🔑 API Key 1 Public: ${apiKey1.publicKey}`);
    console.log(`🔑 API Key 2 Public: ${apiKey2.publicKey}`);

    // 2. Create first client (API Key Index 0)
    console.log("\n📋 Creating first client (API Key Index 0)...");
    await signer.createClient(
      URL,
      apiKey1.privateKey,
      CHAIN_ID,
      0, // API Key Index 0
      ACCOUNT_INDEX
    );
    console.log("✅ First client created successfully.");

    // 3. Create second client (API Key Index 1) 
    console.log("\n📋 Creating second client (API Key Index 1)...");
    await signer.createClient(
      URL,
      apiKey2.privateKey,
      CHAIN_ID,
      1, // API Key Index 1
      ACCOUNT_INDEX
    );
    console.log("✅ Second client created successfully.");

    // 4. Test initial client (should be the last created - API Key Index 1)
    console.log("\n📋 Testing current active client...");
    try {
      await signer.checkClient(1, ACCOUNT_INDEX);
      console.log("✅ Current active client is API Key Index 1 (as expected).");
    } catch (error) {
      console.log("ℹ️  Current client check failed - this may be expected if API keys aren't registered on server");
      console.log(`Error: ${error}`);
    }

    // 5. Test switchAPIKey to API Key Index 0
    console.log("\n📋 Testing switchAPIKey to API Key Index 0...");
    await signer.switchAPIKey(0);
    console.log("✅ Successfully switched to API Key Index 0.");

    // 6. Verify the switch worked by checking client
    console.log("\n📋 Verifying switch to API Key Index 0...");
    try {
      await signer.checkClient(0, ACCOUNT_INDEX);
      console.log("✅ Switch to API Key Index 0 verified.");
    } catch (error) {
      console.log("ℹ️  Client check failed - this may be expected if API keys aren't registered on server");
      console.log(`Error: ${error}`);
    }

    // 7. Test switchAPIKey to API Key Index 1
    console.log("\n📋 Testing switchAPIKey to API Key Index 1...");
    await signer.switchAPIKey(1);
    console.log("✅ Successfully switched to API Key Index 1.");

    // 8. Verify the switch worked
    console.log("\n📋 Verifying switch to API Key Index 1...");
    try {
      await signer.checkClient(1, ACCOUNT_INDEX);
      console.log("✅ Switch to API Key Index 1 verified.");
    } catch (error) {
      console.log("ℹ️  Client check failed - this may be expected if API keys aren't registered on server");
      console.log(`Error: ${error}`);
    }

    // 9. Test functional difference by signing with different keys
    console.log("\n📋 Testing functional difference by signing transactions...");
    
    // Switch to API Key 0 and sign a transaction
    await signer.switchAPIKey(0);
    const tx1 = await signer.signCreateSubAccount(301);
    console.log(`✅ Signed transaction with API Key 0. Nonce: ${tx1.Nonce}, ApiKeyIndex: ${tx1.ApiKeyIndex}`);
    
    // Switch to API Key 1 and sign a transaction
    await signer.switchAPIKey(1);
    const tx2 = await signer.signCreateSubAccount(302);
    console.log(`✅ Signed transaction with API Key 1. Nonce: ${tx2.Nonce}, ApiKeyIndex: ${tx2.ApiKeyIndex}`);

    // 10. Verify transactions have different API key indices
    if (tx1.ApiKeyIndex === tx2.ApiKeyIndex) {
      throw new Error("Transactions should have different API key indices");
    }
    if (tx1.ApiKeyIndex !== 0) {
      throw new Error(`Transaction 1 should have API key index 0, got ${tx1.ApiKeyIndex}`);
    }
    if (tx2.ApiKeyIndex !== 1) {
      throw new Error(`Transaction 2 should have API key index 1, got ${tx2.ApiKeyIndex}`);
    }
    
    console.log("✅ Transactions correctly use different API key indices.");

    // 11. Test error case: switch to non-existent API key
    console.log("\n📋 Testing error case: switch to non-existent API key...");
    try {
      await signer.switchAPIKey(99); // Non-existent API key
      throw new Error("Should have failed when switching to non-existent API key");
    } catch (error) {
      if (error instanceof Error && error.message.includes("no client initialized for api key")) {
        console.log("✅ Correctly rejected switch to non-existent API key");
      } else {
        throw error;
      }
    }

    // 12. Verify we can still use a valid API key after error
    console.log("\n📋 Verifying recovery after error...");
    await signer.switchAPIKey(0);
    const tx3 = await signer.signCreateSubAccount(303);
    if (tx3.ApiKeyIndex !== 0) {
      throw new Error("Failed to recover after error case");
    }
    console.log("✅ Successfully recovered and can still use valid API keys.");

    console.log("\n🎉 All switchAPIKey tests passed successfully!");

  } catch (error) {
    console.log("\n❌ FAILED: Smoke detected!");
    console.error("💥 Error:", error);
    process.exit(1);
  }
}

runTest();
