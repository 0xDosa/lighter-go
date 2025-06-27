package txtypes

import (
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks"
)

var _ TxInfo = (*L2UpdateMarginTxInfo)(nil)

type L2UpdateMarginTxInfo struct {
	AccountIndex int64
	ApiKeyIndex  uint8
	MarketIndex  uint8
	USDCAmount   int64 // USDCAmount is given with 6 decimals. Can be negative to remove margin.
	Direction    uint8 // 0 for LONG, 1 for SHORT
	ExpiredAt    int64
	Nonce        int64
	Sig          []byte
	SignedHash   string `json:"-"`
}

func (txInfo *L2UpdateMarginTxInfo) Validate() error {
	if txInfo.AccountIndex <= MinAccountIndex {
		return ErrFromAccountIndexTooLow
	}
	if txInfo.AccountIndex > MaxAccountIndex {
		return ErrFromAccountIndexTooHigh
	}
	if txInfo.ApiKeyIndex > MaxApiKeyIndex {
		return ErrApiKeyIndexTooHigh
	}
	if txInfo.MarketIndex < MinMarketIndex {
		return ErrMarketIndexTooLow
	}
	if txInfo.MarketIndex > MaxMarketIndex {
		return ErrMarketIndexTooHigh
	}
	if txInfo.USDCAmount == 0 {
		return ErrUSDCAmountIsZero
	}
	if txInfo.Nonce < MinNonce {
		return ErrNonceTooLow
	}
	if txInfo.ExpiredAt < 0 || txInfo.ExpiredAt > MaxTimestamp {
		return ErrExpiredAtInvalid
	}
	return nil
}

func (txInfo *L2UpdateMarginTxInfo) GetTxType() uint8 {
	return TxTypeL2UpdateMargin
}

func (txInfo *L2UpdateMarginTxInfo) GetTxHash() string {
	return txInfo.SignedHash
}

func (txInfo *L2UpdateMarginTxInfo) GetTxInfo() (string, error) {
	return getTxInfo(txInfo)
}

func (txInfo *L2UpdateMarginTxInfo) Hash(lighterChainId uint32, extra ...g.Element) (msgHash []byte, err error) {
	elems := make([]g.Element, 0, 9)

	elems = append(elems, g.FromUint32(lighterChainId))
	elems = append(elems, g.FromUint32(TxTypeL2UpdateMargin))
	elems = append(elems, g.FromInt64(txInfo.Nonce))
	elems = append(elems, g.FromInt64(txInfo.ExpiredAt))
	elems = append(elems, g.FromInt64(txInfo.AccountIndex))
	elems = append(elems, g.FromUint32(uint32(txInfo.ApiKeyIndex)))
	elems = append(elems, g.FromUint32(uint32(txInfo.MarketIndex)))
	elems = append(elems, g.FromUint32(uint32(txInfo.Direction)))

	usdcAmountField := g.FromInt64(txInfo.USDCAmount)
	elems = append(elems, usdcAmountField)

	return p2.HashToQuinticExtension(elems).ToLittleEndianBytes(), nil
} 