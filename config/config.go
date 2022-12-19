package config

type Config struct {
	ChainId       string `json:"chain_id,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	PrefixAddress string `json:"prefix_address,omitempty"`
	TokenSymbol   string `json:"token_symbol,omitempty"`
}
