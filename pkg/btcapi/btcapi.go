package btcapi

import (
	"fmt"
	"io"
	"net/http"

	"github.com/aravinddojima/btcd/btcutil"
	"github.com/aravinddojima/btcd/chaincfg/chainhash"
	"github.com/aravinddojima/btcd/wire"
	"github.com/pkg/errors"
)

type UnspentOutput struct {
	Outpoint *wire.OutPoint
	Output   *wire.TxOut
}

type BTCAPIClient interface {
	GetRawTransaction(txHash *chainhash.Hash) (*wire.MsgTx, error)
	BroadcastTx(tx *wire.MsgTx) (*chainhash.Hash, error)
	ListUnspent(address btcutil.Address) ([]*UnspentOutput, error)
}

func Request(method, baseURL, subPath string, requestBody io.Reader) ([]byte, error) {
	url := fmt.Sprintf("%s%s", baseURL, subPath)
	req, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}
	return body, nil
}
