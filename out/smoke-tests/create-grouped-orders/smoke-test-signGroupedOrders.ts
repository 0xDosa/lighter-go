import { SignerWASM, GroupingType } from "../../signer";
import {
  ACCOUNT_INDEX,
  API_KEY_INDEX,
  CHAIN_ID,
  SEED_PHRASE,
  URL,
} from "../base.ts";
import {
  OrderType,
  TimeInForce,
  NilOrderTriggerPrice,
} from "../../signerConstants.ts";

console.log("🧪 Testing signCreateGroupedOrders: OCO, OTO, and OTOCO...");

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

    // Common expiry time for all orders
    const orderExpiry = Date.now() + 1000 * 60 * 60 * 24 * 28; // 28 days

    // 2. Test OCO (One Cancels Other) - Two reduce-only orders
    console.log("\n📋 Testing OCO (One Cancels Other)...");
    const ocoParams = {
      groupingType: GroupingType.OCO,
      orders: [
        {
          marketIndex: 0,
          baseAmount: 401, // Same base amount for both OCO orders
          price: 210000, // Take profit price
          isAsk: 1, // sell
          type: OrderType.TakeProfitOrder,
          timeInForce: TimeInForce.ImmediateOrCancel,
          reduceOnly: 1, // OCO orders must be reduce-only
          triggerPrice: 210000,
          orderExpiry: orderExpiry,
        },
        {
          marketIndex: 0,
          baseAmount: 401, // Same base amount for OCO
          price: 190000, // Stop loss price
          isAsk: 1, // sell (same direction for OCO)
          type: OrderType.StopLossOrder,
          timeInForce: TimeInForce.ImmediateOrCancel,
          reduceOnly: 1, // OCO orders must be reduce-only
          triggerPrice: 190000,
          orderExpiry: orderExpiry, // Same expiry
        },
      ],
      expiredAt: -1,
      nonce: 101,
    };
    console.log("📝 OCO Params:", JSON.stringify(ocoParams, null, 2));

    const signedOCO = await signer.signCreateGroupedOrders(ocoParams);
    if (
      !signedOCO ||
      !signedOCO.Nonce ||
      signedOCO.GroupingType !== GroupingType.OCO
    ) {
      throw new Error("OCO order signing failed.");
    }
    console.log("✅ OCO Order signed successfully.");
    console.log("📄 OCO Signed Tx:", JSON.stringify(signedOCO, null, 2));

    // 3. Test OTO (One Triggers Other) - Primary order triggers child order
    console.log("\n📋 Testing OTO (One Triggers Other)...");
    const otoParams = {
      groupingType: GroupingType.OTO,
      orders: [
        // Primary order: Limit buy order
        {
          marketIndex: 0,
          baseAmount: 401,
          price: 200000,
          isAsk: 0, // buy
          type: OrderType.LimitOrder,
          timeInForce: TimeInForce.GoodTillTime,
          reduceOnly: 0,
          triggerPrice: NilOrderTriggerPrice,
          orderExpiry: orderExpiry,
        },
        // Child order: Take profit (opposite direction, 0 base amount)
        {
          marketIndex: 0,
          baseAmount: 0, // Child orders have 0 base amount in OTO
          price: 1, // Minimal price for child orders
          isAsk: 1, // sell (opposite direction)
          type: OrderType.TakeProfitOrder,
          timeInForce: TimeInForce.ImmediateOrCancel,
          reduceOnly: 1, // Child orders are reduce-only
          triggerPrice: 210000,
          orderExpiry: orderExpiry,
        },
      ],
      expiredAt: -1,
      nonce: 102,
    };
    console.log("📝 OTO Params:", JSON.stringify(otoParams, null, 2));

    const signedOTO = await signer.signCreateGroupedOrders(otoParams);
    if (
      !signedOTO ||
      !signedOTO.Nonce ||
      signedOTO.GroupingType !== GroupingType.OTO
    ) {
      throw new Error("OTO order signing failed.");
    }
    console.log("✅ OTO Order signed successfully.");
    console.log("📄 OTO Signed Tx:", JSON.stringify(signedOTO, null, 2));

    // 4. Test OTOCO (One Triggers Other Cancels Other) - Matching real data pattern
    console.log("\n📋 Testing OTOCO (One Triggers Other Cancels Other)...");
    const otocoParams = {
      groupingType: GroupingType.OTOCO,
      orders: [
        // Primary order: Limit buy order (matches real data pattern)
        {
          marketIndex: 0,
          baseAmount: 401,
          price: 200000,
          isAsk: 0, // buy
          type: OrderType.LimitOrder, // Type 0
          timeInForce: TimeInForce.GoodTillTime, // Type 1
          reduceOnly: 0,
          triggerPrice: NilOrderTriggerPrice, // 0
          orderExpiry: orderExpiry,
        },
        // Child order 1: Take profit (matches real data)
        {
          marketIndex: 0,
          baseAmount: 0, // Child orders have 0 base amount
          price: 1, // Minimal price as in real data
          isAsk: 1, // sell (opposite direction)
          type: OrderType.TakeProfitOrder, // Type 4
          timeInForce: TimeInForce.ImmediateOrCancel, // Type 0
          reduceOnly: 1, // Must be reduce-only
          triggerPrice: 210000, // Take profit trigger
          orderExpiry: orderExpiry,
        },
        // Child order 2: Stop loss (matches real data)
        {
          marketIndex: 0,
          baseAmount: 0, // Child orders have 0 base amount
          price: 1, // Minimal price as in real data
          isAsk: 1, // sell (opposite direction)
          type: OrderType.StopLossOrder, // Type 2
          timeInForce: TimeInForce.ImmediateOrCancel, // Type 0
          reduceOnly: 1, // Must be reduce-only
          triggerPrice: 190000, // Stop loss trigger
          orderExpiry: orderExpiry,
        },
      ],
      expiredAt: -1,
      nonce: 103,
    };
    console.log("📝 OTOCO Params:", JSON.stringify(otocoParams, null, 2));

    const signedOTOCO = await signer.signCreateGroupedOrders(otocoParams);
    if (
      !signedOTOCO ||
      !signedOTOCO.Nonce ||
      signedOTOCO.GroupingType !== GroupingType.OTOCO
    ) {
      throw new Error("OTOCO order signing failed.");
    }
    console.log("✅ OTOCO Order signed successfully.");
    console.log("📄 OTOCO Signed Tx:", JSON.stringify(signedOTOCO, null, 2));

    // Verify the structure matches real data pattern
    console.log("\n🔍 Verifying OTOCO structure matches real data pattern:");
    console.log(
      `AccountIndex: ${signedOTOCO.AccountIndex} (should be ${ACCOUNT_INDEX})`
    );
    console.log(
      `ApiKeyIndex: ${signedOTOCO.ApiKeyIndex} (should be ${API_KEY_INDEX})`
    );
    console.log(`GroupingType: ${signedOTOCO.GroupingType} (should be 3)`);
    console.log(`Orders count: ${signedOTOCO.Orders.length} (should be 3)`);

    if (signedOTOCO.Orders.length === 3) {
      const [primary, takeProfit, stopLoss] = signedOTOCO.Orders;
      console.log(
        `Primary order - BaseAmount: ${primary.BaseAmount}, IsAsk: ${primary.IsAsk}, Type: ${primary.Type}`
      );
      console.log(
        `Take Profit - BaseAmount: ${takeProfit.BaseAmount}, IsAsk: ${takeProfit.IsAsk}, Type: ${takeProfit.Type}, TriggerPrice: ${takeProfit.TriggerPrice}`
      );
      console.log(
        `Stop Loss - BaseAmount: ${stopLoss.BaseAmount}, IsAsk: ${stopLoss.IsAsk}, Type: ${stopLoss.Type}, TriggerPrice: ${stopLoss.TriggerPrice}`
      );
    }

    console.log("\n🎉 All grouped order tests passed successfully!");
  } catch (error) {
    console.log("\n❌ FAILED: Smoke detected!");
    console.error("💥 Error:", error);
    process.exit(1);
  }
}

runTest();
