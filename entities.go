package onesandboxapi

import "fmt"

type SterlingToSterlingTransferRequest struct {
	PrincipalCreditAccount string  `json:"principalCreditAccount"`
	PrincipalAmount        float64 `json:"principalAmount"`
	FeeAmount              float64 `json:"feeAmount"`
	TransactionNarration   string  `json:"transactionNarration"`
	TransactionReference   string  `json:"transactionReference"`
}

type sterlingToSterlingTransferRequest struct {
	SterlingToSterlingTransferRequest
	PrincipalDebitAccount string  `json:"principalDebitAccount"`
	VatDebitAccount       string  `json:"vatDebitAccount"`
	VatCreditAccount      string  `json:"vatCreditAccount"`
	VatAmount             float64 `json:"vatAmount"`
	DebitCurrency         string  `json:"debitCurrency"`
	CreditCurrency        string  `json:"creditCurrency"`
	TransactionDebitType  int64   `json:"transactionDebitType"`
	ChannelID             int     `json:"channelID"`
	TransactionFeeCode    int64   `json:"transactionFeeCode"`
	FtCommissionTypes     string  `json:"ftCommissionTypes"`
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

func (s ErrorResponse) Error() string {
	return fmt.Sprintf("code=%s desc=%s details=%v", s.Code, s.Description, s.Details)
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

type SingleDebitFundsTransferResponse struct {
	Success   bool                                    `json:"success"`
	Content   SingleDebitFundsTransferResponseContent `json:"content"`
	ErrorData *ErrorResponse                          `json:"error"`
	Message   string                                  `json:"message"`
	RequestID string                                  `json:"request_id"`
	TimeTaken string                                  `json:"time_taken"`
}

func (s SingleDebitFundsTransferResponse) Error() string {
	if s.ErrorData == nil {
		return fmt.Sprintf("msg=%s", s.Message)
	}

	return fmt.Sprintf("msg=%s err=%s", s.Message, s.ErrorData.Error())
}

type SingleDebitFundsTransferResponseContent struct {
	PrincipalFTResponse        string `json:"principalFTResponse"`
	VatFTResponse              any    `json:"vatFTResponse"`
	FeeFTResponse              any    `json:"feeFTResponse"`
	UniqueTransactionReference string `json:"uniqueTransactionReference"`
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
	Content      NipTransactionValidationResponseContent `json:"content"`
	Error        *ErrorResponse                          `json:"error"`
	HasError     bool                                    `json:"hasError"`
	ErrorMessage string                                  `json:"errorMessage"`
	Message      string                                  `json:"message"`
	IsSuccess    bool                                    `json:"isSuccess"`
	Success      bool                                    `json:"success"`
	RequestTime  string                                  `json:"requestTime"`
	ResponseTime string                                  `json:"responseTime"`
	SessionID    string                                  `json:"sessionID"`
}

func (s NipTransactionValidationResponse) IsSuccessfullyProcessed() bool {
	return s.Content.IsSuccessfullyProcessed()
}

type NipTransactionValidationResponseContent struct {
	Status       string `json:"status"`
	HasError     bool   `json:"hasError"`
	ErrorMessage string `json:"errorMessage"`
	IsSuccess    bool   `json:"isSuccess"`
	RequestTime  string `json:"requestTime"`
	ResponseTime string `json:"responseTime"`
	SessionID    string `json:"sessionID"`
}

func (s NipTransactionValidationResponseContent) IsSuccessfullyProcessed() bool {
	return s.Status == "S"
}

type SterlingToSterlingTransactionValidationResponse struct {
	Content      SterlingToSterlingTransactionValidationResponseContent `json:"content"`
	Error        *ErrorResponse                                         `json:"error"`
	HasError     bool                                                   `json:"hasError"`
	ErrorMessage string                                                 `json:"errorMessage"`
	Message      string                                                 `json:"message"`
	RequestID    string                                                 `json:"requestId"`
	IsSuccess    bool                                                   `json:"isSuccess"`
	Success      bool                                                   `json:"success"`
	RequestTime  string                                                 `json:"requestTime"`
	ResponseTime string                                                 `json:"responseTime"`
}

func (s SterlingToSterlingTransactionValidationResponse) IsSuccessfullyProcessed() bool {
	return s.Content.IsSuccessfullyProcessed()
}

func (s SterlingToSterlingTransactionValidationResponse) IsUnSuccessfullyProcessed() bool {
	return s.Content.IsUnSuccessfullyProcessed()
}

type SterlingToSterlingTransactionValidationResponseContent struct {
	TransactionReference       string      `json:"transactionReference"`
	TransactionStatus          string      `json:"transactionStatus"`
	TransactionStatusVat       interface{} `json:"transactionStatusVat"`
	BranchCode                 string      `json:"branchCode"`
	PrincipalResponse          string      `json:"principalResponse"`
	FeeResponse                interface{} `json:"feeResponse"`
	UniqueTransactionReference string      `json:"uniqueTransactionReference"`
	VatResponse                interface{} `json:"vatResponse"`
}

func (s SterlingToSterlingTransactionValidationResponseContent) IsSuccessfullyProcessed() bool {
	return s.TransactionStatus == "PROCESSED"
}

func (s SterlingToSterlingTransactionValidationResponseContent) IsUnSuccessfullyProcessed() bool {
	return s.TransactionStatus == "ERROR"
}
