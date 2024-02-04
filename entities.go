package onesandboxapi

type SterlingToSterlingTransferRequest struct {
	PrincipalDebitAccount  string  `json:"principalDebitAccount"`
	PrincipalCreditAccount string  `json:"principalCreditAccount"`
	PrincipalAmount        float64 `json:"principalAmount"`
	FeeAmount              float64 `json:"feeAmount"`
	VatDebitAccount        string  `json:"vatDebitAccount"`
	VatCreditAccount       string  `json:"vatCreditAccount"`
	VatAmount              float64 `json:"vatAmount"`
	DebitCurrency          string  `json:"debitCurrency"`
	CreditCurrency         string  `json:"creditCurrency"`
	TransactionDebitType   int64   `json:"transactionDebitType"`
	ChannelID              int     `json:"channelID"`
	TransactionNarration   string  `json:"transactionNarration"`
	TransactionReference   string  `json:"transactionReference"`
	TransactionFeeCode     int64   `json:"transactionFeeCode"`
	FtCommissionTypes      string  `json:"ftCommissionTypes"`
}

type NipAccountNameLookupRequest struct {
	SessionID                  string `json:"sessionID"`
	DestinationInstitutionCode string `json:"destinationInstitutionCode"`
	ChannelCode                int64  `json:"channelCode"`
	AccountNumber              string `json:"accountNumber"`
}

type NipOutwardTransferRequest struct {
	NameEnquirySessionID string `json:"nameEnquirySessionID"`
	TransactionCode      string `json:"transactionCode"`
	ChannelCode          int64  `json:"channelCode"`
	PaymentReference     string `json:"paymentReference"`
	Amount               int64  `json:"amount"`
	CreditAccountName    string `json:"creditAccountName"`
	CreditAccountNumber  string `json:"creditAccountNumber"`
	OriginatorName       string `json:"originatorName"`
	BranchCode           string `json:"branchCode"`
	CustomerID           string `json:"customerID"`
	CurrencyCode         string `json:"currencyCode"`
	LedgerCode           string `json:"ledgerCode"`
	SubAccountCode       string `json:"subAccountCode"`
	NameEnquiryResponse  string `json:"nameEnquiryResponse"`
	DebitAccountNumber   string `json:"debitAccountNumber"`
	BeneficiaryBankCode  string `json:"beneficiaryBankCode"`
	OriginatorBVN        string `json:"originatorBVN"`
	BeneficiaryBVN       string `json:"beneficiaryBVN"`
	BeneficiaryKYCLevel  string `json:"beneficiaryKYCLevel"`
	OriginatorKYCLevel   string `json:"originatorKYCLevel"`
	TransactionLocation  string `json:"transactionLocation"`
	AppID                int64  `json:"appId"`
	PriorityLevel        int64  `json:"priorityLevel"`
	IsWalletTransaction  bool   `json:"isWalletTransaction"`
}

type ErrorResponse struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Details     any    `json:"details"`
}

type ChannelBearerTokenResponse struct {
	Success   bool                              `json:"success"`
	Content   ChannelBearerTokenResponseContent `json:"content"`
	Error     *ErrorResponse                    `json:"error"`
	Message   string                            `json:"message"`
	RequestID string                            `json:"request_id"`
	TimeTaken string                            `json:"time_taken"`
}

type ChannelBearerTokenResponseContent struct {
	BearerToken string `json:"bearerToken"`
	ExpiryTime  string `json:"expiryTime"`
}

type AuthTokenResponse struct {
	Success   bool                     `json:"success"`
	Content   AuthTokenResponseContent `json:"content"`
	Error     *ErrorResponse           `json:"error"`
	Message   string                   `json:"message"`
	RequestID string                   `json:"request_id"`
	TimeTaken string                   `json:"time_taken"`
}

type AuthTokenResponseContent struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type NipNameEnquiryResponse struct {
	Success   bool                          `json:"success"`
	Content   NipNameEnquiryResponseContent `json:"content"`
	Error     *ErrorResponse                `json:"error"`
	Message   string                        `json:"message"`
	RequestID string                        `json:"request_id"`
	TimeTaken string                        `json:"time_taken"`
}

type SingleDebitFundsTransferResponse struct {
	Success   bool                                    `json:"success"`
	Content   SingleDebitFundsTransferResponseContent `json:"content"`
	Error     *ErrorResponse                          `json:"error"`
	Message   string                                  `json:"message"`
	RequestID string                                  `json:"request_id"`
	TimeTaken string                                  `json:"time_taken"`
}

type SingleDebitFundsTransferResponseContent struct {
	PrincipalFTResponse        string `json:"principalFTResponse"`
	VatFTResponse              any    `json:"vatFTResponse"`
	FeeFTResponse              any    `json:"feeFTResponse"`
	UniqueTransactionReference string `json:"uniqueTransactionReference"`
}

type NipNameEnquiryResponseContent struct {
	SessionID                  string `json:"sessionID"`
	DestinationInstitutionCode string `json:"destinationInstitutionCode"`
	ChannelCode                int64  `json:"channelCode"`
	AccountNumber              string `json:"accountNumber"`
	AccountName                string `json:"accountName"`
	BankVerificationNumber     string `json:"bankVerificationNumber"`
	KycLevel                   string `json:"kycLevel"`
	ResponseCode               string `json:"responseCode"`
}

type NipTransferResponse struct {
	Success   bool           `json:"success"`
	Content   string         `json:"content"`
	Error     *ErrorResponse `json:"error"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id"`
	TimeTaken string         `json:"time_taken"`
}

type NipTransactionValidationResponse struct {
	Content      Content        `json:"content"`
	Error        *ErrorResponse `json:"error"`
	HasError     bool           `json:"hasError"`
	ErrorMessage string         `json:"errorMessage"`
	Message      string         `json:"message"`
	IsSuccess    bool           `json:"isSuccess"`
	RequestTime  string         `json:"requestTime"`
	ResponseTime string         `json:"responseTime"`
	SessionID    string         `json:"sessionID"`
}

type Content struct {
	Status string `json:"status"`
}
