package onesandboxapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/gommon/random"
	"github.com/payedhq/onesandboxapi/encryption"
	"github.com/sirupsen/logrus"
)

var ErrInternalServer = errors.New("internal server error")

type Config struct {
	Key                string
	IV                 string
	BaseUrl            string
	Email              string
	Password           string
	NipTargetToken     string
	ChannelId          string
	DebitAccountNumber string
	OriginatorName     string
	CustomerId         string
}

type ApiService struct {
	config            *Config
	httpClient        *http.Client
	accessToken       string
	targetBearerToken string
	appId             int
	expiresAt         time.Time
	logger            *logrus.Entry
}

func NewApiService(apiServiceConfig Config, logger *logrus.Entry) *ApiService {
	appId, _ := strconv.Atoi(apiServiceConfig.ChannelId)
	return &ApiService{
		config: &apiServiceConfig,
		httpClient: &http.Client{
			Timeout: time.Minute * 2,
		},
		appId:  appId,
		logger: logger,
	}
}

func (a *ApiService) InitiateNibsOutwardFundsTransferSingleDebit(
	ctx context.Context,
	nipNameEnqResult *NipNameEnquiryResponseContent,
	outwardTransferReq NipOutwardTransferRequest,
) (*NipTransferResponse, error) {

	if err := a.setAccessToken(); err != nil {
		return nil, fmt.Errorf("set access token: %w", err)
	}

	a.logger.WithField("nipNameEnqResult", nipNameEnqResult).Info("completed nip name enquiry")

	appId, _ := strconv.ParseInt(a.config.ChannelId, 10, 64)
	outwardTransferReq.AppID = appId
	outwardTransferReq.OriginatorName = a.config.OriginatorName
	outwardTransferReq.DebitAccountNumber = a.config.DebitAccountNumber

	transferPayload, err := json.Marshal(outwardTransferReq)
	if err != nil {
		a.logger.WithError(err).WithField("outwardTransferReq", outwardTransferReq).Error("could not marshal nib outbound req")
		return nil, fmt.Errorf("nib outbound req: %w", err)
	}

	a.logger.WithField("transferPayload", string(transferPayload)).Info("nip transfer request decoded")

	encodedTransferData, err := encryption.EncryptAES(string(transferPayload), a.config.Key, a.config.IV)
	if err != nil {
		a.logger.WithError(err).WithField("payload", transferPayload).Error("could not encode nibbs payload")
		return nil, fmt.Errorf("nibbs payload: %w", err)
	}

	nipNameTransferEnqResult, err := a.makeNibsOutwardFundsTransferSingleDebit(encodedTransferData, a.accessToken, a.config.NipTargetToken)
	if err != nil {
		a.logger.WithError(err).WithField("encodedData", encodedTransferData).Error("could not make nibbs transfer request")
		return nil, fmt.Errorf("nibbs transfer request: %w", err)
	}

	a.logger.WithField("nipNameTransferEnqResult", nipNameTransferEnqResult).Info("completed nip transfer")

	return nipNameTransferEnqResult, nil
}

func (a *ApiService) NipNameEnquiry(
	accountNumber, bankCode string,
) (*NipNameEnquiryResponseContent, error) {

	if err := a.setAccessToken(); err != nil {
		return nil, fmt.Errorf("set access token: %w", err)
	}

	sessionId := generateSessionId()
	nipAccountNameLookupReq := NipAccountNameLookupRequest{
		SessionID:                  sessionId,
		DestinationInstitutionCode: bankCode,
		ChannelCode:                2,
		AccountNumber:              accountNumber,
	}

	nipAccountNameLookupReqBytes, err := json.Marshal(nipAccountNameLookupReq)
	if err != nil {
		a.logger.WithError(err).WithField("nipAccountNameLookupReq", nipAccountNameLookupReq).Error("could not convert nipAccountNameLookupReq to json")
		return nil, fmt.Errorf("nipAccountNameLookupReq to json: %w", err)
	}

	payload := string(nipAccountNameLookupReqBytes)

	a.logger.WithField("payload", payload).Info("Nibs name enquiry payload")

	encodedData, err := encryption.EncryptAES(payload, a.config.Key, a.config.IV)
	if err != nil {
		a.logger.WithError(err).WithField("payload", payload).Error("could not encode nibbs payload")
		return nil, fmt.Errorf("encode nibbs payload: %w", err)
	}

	nipNameEnqResult, err := a.makeNibsOutwardNameEnquiry(encodedData, a.accessToken, a.config.NipTargetToken)
	if err != nil {
		a.logger.WithError(err).WithField("encodedData", encodedData).Error("could not make nibbs name enquiry request")
		return nil, fmt.Errorf("nibbs name enquiry request: %w", err)
	}

	a.logger.WithField("nipNameEnqResult", nipNameEnqResult).Info("completed nip name enquiry")
	return nipNameEnqResult, nil
}

func (a *ApiService) NipTransactionValidation(
	sessionId string,
) (*NipTransactionValidationResponse, error) {

	if err := a.setAccessToken(); err != nil {
		return nil, fmt.Errorf("set access token: %w", err)
	}

	nipTransactionValidationReq := map[string]any{
		"sessionID": sessionId,
	}

	nipTransactionValidationReqBytes, err := json.Marshal(nipTransactionValidationReq)
	if err != nil {
		a.logger.WithError(err).WithField("nipTransactionValidationReq", nipTransactionValidationReq).Error("could not convert nipTransactionValidationReq to json")
		return nil, fmt.Errorf("nipAccountNameLookupReq to json: %w", err)
	}

	payload := string(nipTransactionValidationReqBytes)

	a.logger.WithField("payload", payload).Info("Nibs transaction validation payload")

	encodedData, err := encryption.EncryptAES(payload, a.config.Key, a.config.IV)
	if err != nil {
		a.logger.WithError(err).WithField("payload", payload).Error("could not encode nibbs payload")
		return nil, fmt.Errorf("encode nibbs payload: %w", err)
	}

	nipNameEnqResult, err := a.makeNipTransactionValidation(encodedData, a.accessToken, a.config.NipTargetToken)
	if err != nil {
		a.logger.WithError(err).WithField("encodedData", encodedData).Error("could not make nip transaction validation request")
		return nil, fmt.Errorf("nip transaction validation request: %w", err)
	}

	a.logger.WithField("validationResult", nipNameEnqResult).Info("nip transaction validation request completed")
	return nipNameEnqResult, nil
}

func (a *ApiService) InitiateFundsTransferSingleDebit(
	ctx context.Context,
	input SterlingToSterlingTransferRequest,
) (*SingleDebitFundsTransferResponse, error) {

	if err := a.setAccessToken(); err != nil {
		return nil, fmt.Errorf("set access token: %w", err)
	}
	sterlingToSterlingReq := sterlingToSterlingTransferRequest{
		SterlingToSterlingTransferRequest: input,
	}

	sterlingToSterlingReq.PrincipalDebitAccount = a.config.DebitAccountNumber
	sterlingToSterlingReq.ChannelID = a.appId
	sterlingToSterlingReq.TransactionDebitType = 2
	sterlingToSterlingReq.TransactionFeeCode = 910
	sterlingToSterlingReq.CreditCurrency = "NGN"
	sterlingToSterlingReq.DebitCurrency = "NGN"

	sterlingToSterlingReqBytes, err := json.Marshal(sterlingToSterlingReq)
	if err != nil {
		a.logger.WithError(err).WithField("sterlingToSterlingReq", sterlingToSterlingReq).Error("could not convert sterlingToSterlingReq to json")
		return nil, fmt.Errorf("convert sterlingToSterlingReq to json: %w", err)
	}

	plaintext := string(sterlingToSterlingReqBytes)

	a.logger.WithField("plainPayload", plaintext).Info("about to encrypt payload for transfer")
	ciphertext, err := encryption.EncryptAES(plaintext, a.config.Key, a.config.IV)
	if err != nil {
		a.logger.WithError(err).WithField("plaintext", plaintext).Error("could not encrypt payload")
		return nil, fmt.Errorf("could not encrypt payload: %w", err)
	}

	a.logger.WithField("encryptedPayload", ciphertext).Info("done with encrypting payload for transfer")

	targetBearer := a.targetBearerToken
	authBearer := a.accessToken

	logger := a.logger.WithFields(map[string]any{
		"targetBearer": targetBearer,
		"authBearer":   authBearer,
	})

	result, err := a.makeFundsTransferSingleDebit(ciphertext, authBearer, targetBearer)
	if err != nil {
		logger.WithError(err).WithField("result", result).Error("could not initiate funds transfer single")
		return nil, fmt.Errorf("initiate funds transfer single: %w", err)
	}

	return result, nil
}

func (a *ApiService) setAccessToken() error {

	if a.accessToken != "" && a.targetBearerToken != "" && !a.expiresAt.IsZero() && time.Now().Before(a.expiresAt) {
		a.logger.Info("access token and target token still valid")
		return nil
	}

	a.logger.Info("attempting to generate access token..")
	accessTokenResult, err := a.generateAccessToken(a.config.Email, a.config.Password)
	if err != nil || accessTokenResult == nil {
		a.logger.WithError(err).Error("could not generate access token")
		return fmt.Errorf("could not generate access token: %w", err)
	}

	a.logger.WithField("accessToken", accessTokenResult.AccessToken).Info("successfully generated access token")

	targetBearerResultStr, err := a.generateTargetBearerToken(a.config.ChannelId, accessTokenResult.AccessToken)
	if err != nil {
		a.logger.WithError(err).Error("could not generate target bearer token")
		return fmt.Errorf("could not generate target bearer token: %w", err)
	}

	a.accessToken = accessTokenResult.AccessToken
	a.targetBearerToken = *targetBearerResultStr
	a.expiresAt = time.Now().Add(time.Minute * 30)

	return nil
}

func (a *ApiService) generateAccessToken(
	email,
	password string,
) (*AuthTokenResponseContent, error) {
	url := fmt.Sprintf("%s/gateway/sandbox/api/Accounts/SignIn", a.config.BaseUrl)
	method := http.MethodPost
	payload := fmt.Sprintf(`{
		"email": "%s",
		"password": "%s"
	}`, email, password)

	body, err := a.makeRequest(url, method, payload, nil)
	if err != nil {
		logrus.WithError(err).Error("request failed with error")
		return nil, fmt.Errorf("access token: %w", err)
	}

	logrus.WithField("response", string(body)).Info("request got response")

	var resultMap AuthTokenResponse
	if err := json.Unmarshal(body, &resultMap); err != nil {
		return nil, fmt.Errorf("access token unmarshal response %v: err %w", string(body), err)
	}

	logrus.WithField("resultMap", resultMap).Info("request got resultMap")

	if !resultMap.Success {
		return nil, fmt.Errorf("access token %s - err %v", resultMap.Message, resultMap.Error)
	}

	return &resultMap.Content, nil
}

func (a *ApiService) generateTargetBearerToken(
	channelId, accessToken string,
) (*string, error) {

	method := http.MethodGet
	url := fmt.Sprintf("%s/gateway/fundtransfer/api/v1/authentication/gettoken?channelId=%s", a.config.BaseUrl, channelId)

	targetBearerResultStr, err := a.makeEncyptedRequest(url, method, "", accessToken, nil)
	if err != nil {
		return nil, err
	}

	logrus.WithField("encrypedTargetToken", targetBearerResultStr).Info("successfully generated target token encrypted")

	targetBearerResultStrDecoded, err := encryption.DecryptAES(targetBearerResultStr, a.config.Key, a.config.IV)
	if err != nil {
		logrus.WithError(err).
			WithField("encodedStr", targetBearerResultStr).
			Error("could not decrypt target bearer token")
		return nil, fmt.Errorf("target bearer: %w", err)
	}

	logrus.
		WithField("targetBearerResultStrDecoded", targetBearerResultStrDecoded).
		Info("target bearer result decoded")

	var resultMap ChannelBearerTokenResponse
	if err := json.Unmarshal([]byte(targetBearerResultStrDecoded), &resultMap); err != nil {
		logrus.WithError(err).WithField("decodedStr", targetBearerResultStrDecoded).Error("could not unmarshal target bearer result")
		return nil, fmt.Errorf("target bearer unmarshal: %w", err)
	}

	if !resultMap.Success {
		logrus.WithField("status", resultMap.Success).WithField("resultMap", resultMap).Error("target bearer result is not successful")
		return nil, fmt.Errorf("target bearer response unsuccessful: %s", resultMap.Message)
	}

	targetBearerResult := resultMap.Content
	return &targetBearerResult.BearerToken, nil
}

func (a *ApiService) makeFundsTransferSingleDebit(
	input,
	authBearer,
	targetBearer string,
) (*SingleDebitFundsTransferResponse, error) {

	url := fmt.Sprintf("%s/gateway/fundtransfer/api/v1/fundstransfer/singlecalldebit", a.config.BaseUrl)
	method := http.MethodPost

	result, err := a.makeEncyptedRequest(url, method, input, authBearer, map[string]string{
		"Targetbearer": fmt.Sprintf("Bearer %s", targetBearer),
	})

	logrus.WithField("result", result).WithError(err).Info("feedback from single call debit")

	if result != "" {
		resultDecoded, err := encryption.DecryptAES(result, a.config.Key, a.config.IV)
		if err != nil {
			logrus.WithError(err).
				WithField("encodedStr", result).
				Error("could not decrypt target bearer token")
			return nil, fmt.Errorf("single call debit could not decode response: %w", err)
		}

		logrus.
			WithField("resultDecoded", resultDecoded).
			Info("target response result decoded")

		var resultMap SingleDebitFundsTransferResponse
		if err := json.Unmarshal([]byte(resultDecoded), &resultMap); err != nil {
			logrus.WithError(err).WithField("decodedStr", resultDecoded).Error("could not unmarshal result")
			return nil, fmt.Errorf("single call debit response unmarshal: %w", err)
		}

		if !resultMap.Success {
			logrus.WithField("status", resultMap.Success).WithField("resultMap", resultMap).WithField("Message", resultMap.Message).Error("result is not successful")
			return nil, fmt.Errorf("single call debit could not complete request: %s", resultMap.Message)
		}

		if resultMap.Content.FeeFTResponse == "" {
			logrus.WithField("status", resultMap.Success).WithField("resultMap", resultMap).WithField("Message", resultMap.Message).Error("result is not successful")
			return nil, &resultMap
		}

		return &resultMap, nil
	}

	if err != nil {
		return nil, fmt.Errorf("single call debit: %w", err)
	}

	return nil, fmt.Errorf("single call debit unexpected error making request")
}

func (a *ApiService) makeNipTransactionValidation(
	input,
	authBearer,
	targetBearer string,
) (*NipTransactionValidationResponse, error) {

	url := fmt.Sprintf("%s/gateway/nipoutwardtransaction/api/v1/nipoutwardtransaction/transactionvalidation", a.config.BaseUrl)
	method := http.MethodPost

	result, err := a.makeEncyptedRequest(url, method, input, authBearer, map[string]string{
		"Targetbearer": fmt.Sprintf("Bearer %s", targetBearer),
	})

	logrus.WithField("result", result).WithError(err).Info("feedback from nip transaction validation")

	if result != "" {
		resultDecoded, err := encryption.DecryptAES(result, a.config.Key, a.config.IV)
		if err != nil {
			logrus.WithError(err).
				WithField("encodedStr", result).
				Error("could not decrypt target bearer token")
			return nil, fmt.Errorf("nip transaction validation could not decode response: %w", err)
		}

		logrus.
			WithField("resultDecoded", resultDecoded).
			Info("target response result decoded")

		var resultMap NipTransactionValidationResponse
		if err := json.Unmarshal([]byte(resultDecoded), &resultMap); err != nil {
			logrus.WithError(err).WithField("decodedStr", resultDecoded).Error("could not unmarshal result")
			return nil, fmt.Errorf("nip transaction validation response unmarshal: %w", err)
		}

		if !resultMap.IsSuccess {
			logrus.WithField("status", resultMap.IsSuccess).WithField("resultMap", resultMap).WithField("Message", resultMap.Message).Error("result is not successful")
			return nil, fmt.Errorf("nip transaction validation could not complete request: %s", resultMap.Message)
		}

		return &resultMap, nil
	}

	if err != nil {
		return nil, fmt.Errorf("nip transaction validation: %w", err)
	}

	return nil, fmt.Errorf("nip transaction validation unexpected error making request")
}

func (a *ApiService) makeNibsOutwardNameEnquiry(
	input,
	authBearer,
	targetBearer string,
) (*NipNameEnquiryResponseContent, error) {

	url := fmt.Sprintf("%s/gateway/nipoutwardtransaction/api/v1/nipoutwardtransaction/nameenquiry", a.config.BaseUrl)
	method := http.MethodPost

	result, err := a.makeEncyptedRequest(url, method, input, authBearer, map[string]string{
		"Targetbearer": fmt.Sprintf("Bearer %s", targetBearer),
	})

	logrus.WithField("result", result).WithError(err).Info("feedback from nip name enquiry")

	if result != "" {
		resultDecoded, err := encryption.DecryptAES(result, a.config.Key, a.config.IV)
		if err != nil {
			logrus.WithError(err).
				WithField("encodedStr", result).
				Error("could not decrypt target bearer token")
			return nil, fmt.Errorf("nip name enquiry could not decode response: %w", err)
		}

		logrus.
			WithField("resultDecoded", resultDecoded).
			Info("target response result decoded")

		var resultMap NipNameEnquiryResponse
		if err := json.Unmarshal([]byte(resultDecoded), &resultMap); err != nil {
			logrus.WithError(err).WithField("decodedStr", resultDecoded).Error("could not unmarshal result")
			return nil, fmt.Errorf("nip name enquiry response unmarshal: %w", err)
		}

		if !resultMap.Success {
			logrus.WithField("status", resultMap.Success).WithField("resultMap", resultMap).WithField("Message", resultMap.Message).Error("result is not successful")
			return nil, fmt.Errorf("nip name enquiry could not complete request: %s", resultMap.Message)
		}

		return &resultMap.Content, nil
	}

	if err != nil {
		return nil, fmt.Errorf("nip name enquiry: %w", err)
	}

	return nil, fmt.Errorf("nip name enquiry unexpected error making request")
}

func (a *ApiService) makeNibsOutwardFundsTransferSingleDebit(
	input,
	authBearer,
	targetBearer string,
) (*NipTransferResponse, error) {

	url := fmt.Sprintf("%s/gateway/nipoutwardtransaction/api/v1/nipoutwardtransaction/fundstransfer", a.config.BaseUrl)
	method := http.MethodPost

	result, err := a.makeEncyptedRequest(url, method, input, authBearer, map[string]string{
		"Targetbearer": fmt.Sprintf("Bearer %s", targetBearer),
	})

	logrus.WithField("result", result).WithError(err).Info("feedback from nip transfer")

	if result != "" {
		resultDecoded, err := encryption.DecryptAES(result, a.config.Key, a.config.IV)
		if err != nil {
			logrus.WithError(err).
				WithField("encodedStr", result).
				Error("could not decrypt target bearer token")
			return nil, fmt.Errorf("nip transfer could not decode response: %w", err)
		}

		logrus.
			WithField("resultDecoded", resultDecoded).
			Info("nip transfer target response result decoded")

		var resultMap NipTransferResponse
		if err := json.Unmarshal([]byte(resultDecoded), &resultMap); err != nil {
			logrus.WithError(err).WithField("decodedStr", resultDecoded).Error("could not unmarshal result")
			return nil, fmt.Errorf("nip transfer response unmarshal: %w", err)
		}
		return &resultMap, nil
	}

	if err != nil {
		return nil, fmt.Errorf("nip name enquiry: %w", err)
	}

	return nil, fmt.Errorf("nip name enquiry unexpected error making request")
}

func generateSessionId() string {
	yyMMddHHmmss := "060102150405"
	timeStamp := time.Now().Format(yyMMddHHmmss)
	randomStr := random.String(12, random.Numeric)
	sessionId := fmt.Sprintf("000001%s%s", timeStamp, randomStr)

	return sessionId
}

func (a *ApiService) makeRequest(
	url,
	method,
	input string,
	headers map[string]string,
) ([]byte, error) {
	payload := strings.NewReader(input)

	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	logrus.WithFields(map[string]any{
		"method":  method,
		"url":     url,
		"input":   input,
		"headers": headers,
	}).Info("attempting to send api request")
	res, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	if res.Body != nil {
		defer res.Body.Close()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	logrus.
		WithField("body", string(body)).
		WithField("headers", res.Header.Clone()).
		Info("response recevied")

	if res.StatusCode > 299 || res.StatusCode < 200 {

		if res.StatusCode >= 500 {
			return nil, errors.Join(ErrInternalServer, fmt.Errorf("unsuccessful response: status=%s code=%d, result %s", res.Status, res.StatusCode, string(body)))
		}

		return nil, fmt.Errorf("unsuccessful response: status=%s code=%d, result %s", res.Status, res.StatusCode, string(body))
	}

	return body, nil
}

func (a *ApiService) makeEncyptedRequest(
	url,
	method,
	input,
	authBearer string,
	headers map[string]string,
) (string, error) {
	wrappedInput := ""

	var payload io.Reader
	if input != "" {
		wrappedInput = fmt.Sprintf(`{"data": "%s"}`, input)
		payload = strings.NewReader(wrappedInput)
	}

	logrus.WithField("url", url).
		WithField("method", method).
		WithField("authorization", authBearer).
		WithField("headers", headers).
		WithField("payload", wrappedInput).Info("making encrypted api request")

	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authBearer))

	if len(headers) > 0 {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}

	res, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}
	if res.Body != nil {
		defer res.Body.Close()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	var resultMap map[string]any
	var resultStr string
	if len(body) > 0 {
		if err := json.Unmarshal(body, &resultMap); err != nil {
			return "", fmt.Errorf("could not unmarshal response %v: err %w", string(body), err)
		}
		if resultDataStrVal, ok := resultMap["Data"].(string); ok {
			resultStr = resultDataStrVal
		}
	}

	if res.StatusCode > 299 || res.StatusCode < 200 {

		if res.StatusCode >= 500 {
			return "", errors.Join(ErrInternalServer, fmt.Errorf("unsuccessful response: status=%s code=%d, result %s", res.Status, res.StatusCode, string(body)))
		}

		return resultStr, fmt.Errorf("unsuccessful response: status=%s code=%d, result %s", res.Status, res.StatusCode, string(body))
	}

	logrus.
		WithField("body", string(body)).
		WithField("data", resultStr).
		WithField("headers", res.Header.Clone()).
		Info("response recevied")

	return resultStr, nil
}
