// TypeScript interface for the Go WASM Signer library
import {
  BurnSharesTx,
  CancelAllOrdersTx,
  CancelOrderTx,
  ChangePubKeyTx,
  CreateOrderTx,
  CreateGroupedOrdersTx,
  CreatePublicPoolTx,
  CreateSubAccountTx,
  MintSharesTx,
  ModifyOrderTx,
  TransferTx,
  UpdateLeverageTx,
  UpdateMarginTx,
  UpdatePublicPoolTx,
  WithdrawTx,
} from "./signerTypes";

// Types for the API responses
export interface APIKeyResponse {
  privateKey: string;
  publicKey: string;
  error?: string;
}

export interface ErrorResponse {
  error?: string;
}

export interface TransactionResponse {
  result: string; // JSON string containing transaction data
  error?: string;
}

// Utility interface for CreateOrder parameters
export interface CreateOrderParams {
  marketIndex: number;
  clientOrderIndex: number;
  baseAmount: number;
  price: number;
  isAsk: number; // 0 = buy, 1 = sell
  orderType: number;
  timeInForce: number;
  reduceOnly: number;
  triggerPrice: number;
  orderExpiry: number; // -1 for default (28 days)
  nonce: number; // -1 for auto
}

// Utility interface for individual orders in grouped orders
export type GroupedOrderParams = Omit<
  CreateOrderParams,
  "nonce" | "clientOrderIndex"
>;

// Utility interface for CreateGroupedOrders parameters
export interface CreateGroupedOrdersParams {
  groupingType:
    | typeof GroupingType.OCO
    | typeof GroupingType.OTO
    | typeof GroupingType.OTOCO; // OCO=2, OTO=1, OTOCO=3
  orders: GroupedOrderParams[];
  expiredAt: number; // -1 for default
  nonce: number; // -1 for auto
}

// Constants for grouping types
export const GroupingType = {
  /** One Triggers the Other */
  OTO: 1,
  /** One Cancels the Other */
  OCO: 2,
  /** One Triggers a One Cancels the Other */
  OTOCO: 3,
} as const;

// Global declarations for Go WASM functions
declare global {
  // Key generation
  function generateAPIKey(seed?: string): string;

  // Client management
  function createClient(
    url: string,
    privateKey: string,
    chainId: number,
    apiKeyIndex: number,
    accountIndex: number
  ): string;
  function checkClient(apiKeyIndex: number, accountIndex: number): string;

  // Transaction signing functions
  function signChangePubKey(pubKey: string, nonce: number): string;
  function signCreateOrder(
    marketIndex: number,
    clientOrderIndex: number,
    baseAmount: number,
    price: number,
    isAsk: number,
    orderType: number,
    timeInForce: number,
    reduceOnly: number,
    triggerPrice: number,
    orderExpiry: number,
    nonce: number
  ): string;
  function signCreateGroupedOrders(
    groupingType: number,
    ordersJSON: string,
    expiredAt: number,
    nonce: number
  ): string;
  function signCancelOrder(
    marketIndex: number,
    orderIndex: number,
    nonce: number
  ): string;
  function signWithdraw(usdcAmount: number, nonce: number): string;
  function signCreateSubAccount(nonce: number): string;
  function signCancelAllOrders(
    timeInForce: number,
    time: number,
    nonce: number
  ): string;
  function signModifyOrder(
    marketIndex: number,
    index: number,
    baseAmount: number,
    price: number,
    triggerPrice: number,
    nonce: number
  ): string;
  function signTransfer(
    toAccountIndex: number,
    usdcAmount: number,
    fee: number,
    memo: string,
    nonce: number
  ): string;
  function signCreatePublicPool(
    operatorFee: number,
    initialTotalShares: number,
    minOperatorShareRate: number,
    nonce: number
  ): string;
  function signUpdatePublicPool(
    publicPoolIndex: number,
    status: number,
    operatorFee: number,
    minOperatorShareRate: number,
    nonce: number
  ): string;
  function signMintShares(
    publicPoolIndex: number,
    shareAmount: number,
    nonce: number
  ): string;
  function signBurnShares(
    publicPoolIndex: number,
    shareAmount: number,
    nonce: number
  ): string;
  function signUpdateLeverage(
    marketIndex: number,
    initialMarginFraction: number,
    marginMode: number,
    nonce: number
  ): string;
  function signUpdateMargin(
    marketIndex: number,
    usdcAmount: number,
    direction: number,
    nonce: number
  ): string;

  // Auth token creation
  function createAuthToken(deadline?: number): string;

  // API key switching
  function switchAPIKey(apiKeyIndex: number): string;

  // Go WASM runtime class
  class Go {
    argv: string[];
    env: Record<string, string>;
    exit: (code: number) => void;
    importObject: WebAssembly.Imports;
    run(instance: WebAssembly.Instance): Promise<void>;
  }
}

export class SignerWASM {
  private static instance: SignerWASM | null = null;
  private wasmReady: boolean = false;
  public loadingPromise: Promise<void> | null = null;

  private constructor() {}

  public static getInstance(): SignerWASM {
    if (SignerWASM.instance === null) {
      SignerWASM.instance = new SignerWASM();
    }
    return SignerWASM.instance;
  }

  /**
   * Initialize the WASM module
   */
  private async initializeWASM(): Promise<void> {
    try {
      // Load wasm_exec.js in Node.js environment
      if (typeof (globalThis as any).Go === "undefined") {
        // @ts-ignore - wasm_exec.js is a Go-generated JS file
        await import("./wasm_exec.js");
      }

      const go = new Go();

      let wasmModule: WebAssembly.WebAssemblyInstantiatedSource;

      const isNode =
        typeof process !== "undefined" &&
        process.versions != null &&
        process.versions.node != null;

      if (isNode) {
        // Node.js environment
        const fs = require("fs");
        const path = require("path");
        const wasmBuffer = fs.readFileSync(path.join(__dirname, "signer.wasm"));
        wasmModule = await WebAssembly.instantiate(wasmBuffer, go.importObject);
      } else {
        // Browser environment
        wasmModule = await WebAssembly.instantiateStreaming(
          fetch("/wasm/signer.wasm"),
          go.importObject
        );
      }

      // Start the Go program (don't await - it runs indefinitely)
      go.run(wasmModule.instance);

      // Wait for the Go exports to be available
      let retries = 50; // 5 seconds max
      while (
        retries > 0 &&
        typeof (globalThis as any).generateAPIKey === "undefined"
      ) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        retries--;
      }

      if (typeof (globalThis as any).generateAPIKey === "undefined") {
        throw new Error("WASM functions not exported after waiting");
      }

      this.wasmReady = true;
      console.log("WASM Signer module loaded successfully");
    } catch (error) {
      console.error("Failed to load WASM module:", error);
      throw new Error(`WASM initialization failed: ${error}`);
    }
  }

  /**
   * Ensure WASM is ready before calling functions
   */
  private async ensureReady(): Promise<void> {
    if (!this.wasmReady) {
      if (!this.loadingPromise) {
        this.loadingPromise = this.initializeWASM();
      }
      await this.loadingPromise;
    }
  }

  /**
   * Generate a new API key pair
   * @param seed Optional seed for deterministic key generation
   * @returns Promise containing the generated key pair
   */
  async generateAPIKey(seed?: string): Promise<APIKeyResponse> {
    await this.ensureReady();

    try {
      const result = globalThis.generateAPIKey(seed || "");
      const response: APIKeyResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return {
        privateKey: response.privateKey,
        publicKey: response.publicKey,
      };
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`Key generation failed: ${error}`);
    }
  }

  /**
   * Create a client for transaction signing
   * @param url HTTP client URL
   * @param privateKey Hex-encoded private key
   * @param chainId Blockchain chain ID
   * @param apiKeyIndex API key index
   * @param accountIndex Account index (must be > 0)
   */
  async createClient(
    url: string,
    privateKey: string,
    chainId: number,
    apiKeyIndex: number,
    accountIndex: number
  ): Promise<void> {
    await this.ensureReady();

    try {
      const result = globalThis.createClient(
        url,
        privateKey,
        chainId,
        apiKeyIndex,
        accountIndex
      );
      const response: ErrorResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`Client creation failed: ${error}`);
    }
  }

  /**
   * Check if the client configuration matches and validate against Lighter service
   * @param apiKeyIndex Expected API key index
   * @param accountIndex Expected account index
   */
  async checkClient(apiKeyIndex: number, accountIndex: number): Promise<void> {
    await this.ensureReady();

    try {
      const result = globalThis.checkClient(apiKeyIndex, accountIndex);
      const response: ErrorResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`Client validation failed: ${error}`);
    }
  }

  /**
   * Sign a change public key transaction
   * @param pubKey New public key (hex-encoded, 40 bytes)
   * @param nonce Transaction nonce
   * @returns Transaction object with MessageToSign field
   */
  async signChangePubKey(
    pubKey: string,
    nonce: number
  ): Promise<ChangePubKeyTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signChangePubKey(pubKey, nonce);
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as ChangePubKeyTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignChangePubKey failed: ${error}`);
    }
  }

  /**
   * Sign a create order transaction
   * @param params Order parameters
   * @returns Transaction object
   */
  async signCreateOrder(params: CreateOrderParams): Promise<CreateOrderTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signCreateOrder(
        params.marketIndex,
        params.clientOrderIndex,
        params.baseAmount,
        params.price,
        params.isAsk,
        params.orderType,
        params.timeInForce,
        params.reduceOnly,
        params.triggerPrice,
        params.orderExpiry,
        params.nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as CreateOrderTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignCreateOrder failed: ${error}`);
    }
  }

  /**
   * Sign a create grouped orders transaction
   * @param params Grouped orders parameters
   * @returns Transaction object
   */
  async signCreateGroupedOrders(
    params: CreateGroupedOrdersParams
  ): Promise<CreateGroupedOrdersTx> {
    await this.ensureReady();

    try {
      // Convert orders array to JSON string for WASM function
      const ordersJSON = JSON.stringify(params.orders);

      const result = globalThis.signCreateGroupedOrders(
        params.groupingType,
        ordersJSON,
        params.expiredAt,
        params.nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as CreateGroupedOrdersTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignCreateGroupedOrders failed: ${error}`);
    }
  }

  /**
   * Sign a cancel order transaction
   * @param marketIndex Market identifier
   * @param orderIndex Order index to cancel
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signCancelOrder(
    marketIndex: number,
    orderIndex: number,
    nonce: number
  ): Promise<CancelOrderTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signCancelOrder(marketIndex, orderIndex, nonce);
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as CancelOrderTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignCancelOrder failed: ${error}`);
    }
  }

  /**
   * Sign a withdraw transaction
   * @param usdcAmount USDC amount to withdraw
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signWithdraw(usdcAmount: number, nonce: number): Promise<WithdrawTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signWithdraw(usdcAmount, nonce);
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as WithdrawTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignWithdraw failed: ${error}`);
    }
  }

  /**
   * Sign a create sub-account transaction
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signCreateSubAccount(nonce: number): Promise<CreateSubAccountTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signCreateSubAccount(nonce);
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as CreateSubAccountTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignCreateSubAccount failed: ${error}`);
    }
  }

  /**
   * Sign a cancel all orders transaction
   * @param timeInForce Time in force type
   * @param time Time parameter
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signCancelAllOrders(
    timeInForce: number,
    time: number,
    nonce: number
  ): Promise<CancelAllOrdersTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signCancelAllOrders(timeInForce, time, nonce);
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as CancelAllOrdersTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignCancelAllOrders failed: ${error}`);
    }
  }

  /**
   * Sign a modify order transaction
   * @param marketIndex Market identifier
   * @param index Order index to modify
   * @param baseAmount New base amount
   * @param price New price
   * @param triggerPrice New trigger price
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signModifyOrder(
    marketIndex: number,
    index: number,
    baseAmount: number,
    price: number,
    triggerPrice: number,
    nonce: number
  ): Promise<ModifyOrderTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signModifyOrder(
        marketIndex,
        index,
        baseAmount,
        price,
        triggerPrice,
        nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as ModifyOrderTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignModifyOrder failed: ${error}`);
    }
  }

  /**
   * Sign a transfer transaction
   * @param toAccountIndex Destination account index
   * @param usdcAmount USDC amount to transfer
   * @param fee Transfer fee amount
   * @param memo 32-byte memo string
   * @param nonce Transaction nonce
   * @returns Transaction object with MessageToSign field
   */
  async signTransfer(
    toAccountIndex: number,
    usdcAmount: number,
    fee: number,
    memo: string,
    nonce: number
  ): Promise<TransferTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signTransfer(toAccountIndex, usdcAmount, fee, memo, nonce);
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as TransferTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignTransfer failed: ${error}`);
    }
  }

  /**
   * Sign a create public pool transaction
   * @param operatorFee Operator fee
   * @param initialTotalShares Initial total shares
   * @param minOperatorShareRate Minimum operator share rate
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signCreatePublicPool(
    operatorFee: number,
    initialTotalShares: number,
    minOperatorShareRate: number,
    nonce: number
  ): Promise<CreatePublicPoolTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signCreatePublicPool(
        operatorFee,
        initialTotalShares,
        minOperatorShareRate,
        nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as CreatePublicPoolTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignCreatePublicPool failed: ${error}`);
    }
  }

  /**
   * Sign an update public pool transaction
   * @param publicPoolIndex Public pool index to update
   * @param status New status
   * @param operatorFee New operator fee
   * @param minOperatorShareRate New minimum operator share rate
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signUpdatePublicPool(
    publicPoolIndex: number,
    status: number,
    operatorFee: number,
    minOperatorShareRate: number,
    nonce: number
  ): Promise<UpdatePublicPoolTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signUpdatePublicPool(
        publicPoolIndex,
        status,
        operatorFee,
        minOperatorShareRate,
        nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as UpdatePublicPoolTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignUpdatePublicPool failed: ${error}`);
    }
  }

  /**
   * Sign a mint shares transaction
   * @param publicPoolIndex Public pool index
   * @param shareAmount Amount of shares to mint
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signMintShares(
    publicPoolIndex: number,
    shareAmount: number,
    nonce: number
  ): Promise<MintSharesTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signMintShares(
        publicPoolIndex,
        shareAmount,
        nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as MintSharesTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignMintShares failed: ${error}`);
    }
  }

  /**
   * Sign a burn shares transaction
   * @param publicPoolIndex Public pool index
   * @param shareAmount Amount of shares to burn
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signBurnShares(
    publicPoolIndex: number,
    shareAmount: number,
    nonce: number
  ): Promise<BurnSharesTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signBurnShares(
        publicPoolIndex,
        shareAmount,
        nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result) as BurnSharesTx;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignBurnShares failed: ${error}`);
    }
  }

  /**
   * Sign an update leverage transaction
   * @param marketIndex Market identifier
   * @param initialMarginFraction Initial margin fraction
   * @param marginMode Margin mode
   * @param nonce Transaction nonce
   * @returns Transaction object
   */
  async signUpdateLeverage(
    marketIndex: number,
    initialMarginFraction: number,
    marginMode: number,
    nonce: number
  ): Promise<UpdateLeverageTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signUpdateLeverage(
        marketIndex,
        initialMarginFraction,
        marginMode,
        nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result);
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignUpdateLeverage failed: ${error}`);
    }
  }

  async signUpdateMargin(
    marketIndex: number,
    usdcAmount: number,
    direction: number,
    nonce: number
  ): Promise<UpdateMarginTx> {
    await this.ensureReady();

    try {
      const result = globalThis.signUpdateMargin(
        marketIndex,
        usdcAmount,
        direction,
        nonce
      );
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return JSON.parse(response.result);
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SignUpdateMargin failed: ${error}`);
    }
  }

  /**
   * Create an authentication token
   * @param deadline Optional Unix timestamp deadline (0 for default 7 hours from now)
   * @returns Auth token string
   */
  async createAuthToken(deadline: number = 0): Promise<string> {
    await this.ensureReady();

    try {
      const result = globalThis.createAuthToken(deadline);
      const response: TransactionResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }

      return response.result;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`CreateAuthToken failed: ${error}`);
    }
  }

  /**
   * Switch to a different API key client
   * @param apiKeyIndex API key index to switch to
   */
  async switchAPIKey(apiKeyIndex: number): Promise<void> {
    await this.ensureReady();

    try {
      const result = globalThis.switchAPIKey(apiKeyIndex);
      const response: ErrorResponse = JSON.parse(result);

      if (response.error) {
        throw new Error(response.error);
      }
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`SwitchAPIKey failed: ${error}`);
    }
  }

  /**
   * Check if the WASM module is ready
   */
  isReady(): boolean {
    return this.wasmReady;
  }

  /**
   * Wait for the WASM module to be ready
   */
  async waitForReady(): Promise<void> {
    await this.ensureReady();
  }
}

// Export the singleton instance as default for convenience
export default SignerWASM;
