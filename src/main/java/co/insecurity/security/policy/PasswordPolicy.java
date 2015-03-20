package co.insecurity.security.policy;

import java.util.Set;

import co.insecurity.security.policy.assertion.PolicyAssertion;

public abstract class PasswordPolicy {

	protected Set<PolicyAssertion> assertions;
	
	public boolean checkCompliance(String password) {
		for (PolicyAssertion assertion : assertions) {
			if (!assertion.isTrueFor(password))
				return false;
		}
		return true;
	}
}