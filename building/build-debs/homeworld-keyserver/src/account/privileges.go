package account

import (
	"authorities"
	"time"
	"fmt"
	"token"
)

type Privilege func(ctx *OperationContext, param string) (string, error)

type TLSSignPrivilege struct {
	authority  *authorities.TLSAuthority
	ishost     bool
	lifespan   time.Duration
	commonname string
	dnsnames   []string
}

func NewTLSGrantPrivilege(authority authorities.Authority, ishost bool, lifespan time.Duration, commonname string, dnsnames []string) (Privilege, error) {
	if authority == nil || lifespan < time.Second || commonname == "" || dnsnames == nil || len(dnsnames) == 0 {
		return nil, fmt.Errorf("Missing parameter to TLS granting privilege.")
	}
	tauth, ok := authority.(*authorities.TLSAuthority)
	if !ok {
		return nil, fmt.Errorf("TLS granting privilege expects a TLS authority.")
	}
	return func(_ *OperationContext, signing_request string) (string, error) {
		return tauth.Sign(signing_request, ishost, lifespan, commonname, dnsnames)
	}, nil
}

func NewSSHGrantPrivilege(authority authorities.Authority, ishost bool, lifespan time.Duration, keyid string, principals []string) (Privilege, error) {
	if authority == nil || lifespan < time.Second || keyid == "" || principals == nil || len(principals) == 0 {
		return nil, fmt.Errorf("Missing parameter to SSH granting privilege.")
	}
	tauth, ok := authority.(*authorities.SSHAuthority)
	if !ok {
		return nil, fmt.Errorf("SSH granting privilege expects a SSH authority.")
	}
	return func(_ *OperationContext, signing_request string) (string, error) {
		return tauth.Sign(signing_request, ishost, lifespan, keyid, principals)
	}, nil
}

func stringInList(value string, within []string) bool {
	for _, elem := range within {
		if value == elem {
			return true
		}
	}
	return false
}

func NewBootstrapPrivilege(allowed_principals []string, lifespan time.Duration, registry *token.TokenRegistry) (Privilege, error) {
	if allowed_principals == nil || len(allowed_principals) == 0 || lifespan < time.Millisecond || registry == nil {
		return nil, fmt.Errorf("Missing parameter to token granting privilege.")
	}
	return func(_ *OperationContext, encoded_principal string) (string, error) {
		principal := string(encoded_principal)
		if !stringInList(principal, allowed_principals) {
			return "", fmt.Errorf("Principal not allowed to be bootstrapped: %s", encoded_principal)
		}
		generated_token := registry.GrantToken(principal, lifespan)
		return generated_token, nil
	}, nil
}

func NewImpersonatePrivilege(getAccount func(string) (*Account, error), scope *Group) (Privilege, error) {
	if getAccount == nil || scope == nil {
		return nil, fmt.Errorf("Missing parameter to impersonation privilege.")
	}
	return func(ctx *OperationContext, new_principal string) (string, error) {
		if !scope.HasMember(new_principal) {
			return "", fmt.Errorf("Attempt to impersonate outside of allowed scope.")
		}
		account, err := getAccount(new_principal)
		if err != nil {
			return "", err
		}
		if account.Principal != new_principal {
			return "", fmt.Errorf("Wrong account returned.")
		}
		ctx.Account = account
		return "", nil
	}, nil
}

func NewConfigurationPrivilege(contents string) (Privilege, error) {
	return func(_ *OperationContext, request string) (string, error) {
		if len(request) != 0 {
			return "", fmt.Errorf("Expected empty request to configuration endpoint.")
		}
		return contents, nil
	}, nil
}