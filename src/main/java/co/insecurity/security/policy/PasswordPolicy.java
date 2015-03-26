package co.insecurity.security.policy;

import java.util.Set;
import java.util.Map;
import java.util.Map.Entry;
import java.util.LinkedHashMap;

import co.insecurity.security.policy.assertion.PolicyAssertion;
import co.insecurity.security.policy.assertion.PolicyAssertion.Result;


/**
 * This abstract class provides the base logic required to programmatically 
 * define a password policy, and implements convenience methods to check 
 * compliance against the policy.
 * <p>
 * A {@code PasswordPolicy} is defined as a set of {@code PolicyAssertion}s 
 * that must all hold true for a given password, in order for that password 
 * to be considered in compliance with the policy.
 * 
 * @author Milo Minderbinder 
 *
 */
public abstract class PasswordPolicy {
	
	/**
	 * The set of {@code PolicyAssertion}s that must all return a successful 
	 * {@code PolicyAssertion.Result} for a given password to comply with this 
	 * {@code PasswordPolicy}
	 */
	protected Set<PolicyAssertion> assertions;
	
	/**
	 * Evaluates the given password against each {@code PolicyAssertion} 
	 * defined by the {@code PasswordPolicy} and returns the results.
	 * <p>
	 * This method returns both successful/passed assertions and failed 
	 * assertions.
	 * 
	 * @param password the password to evaluate against this policy
	 * @return the {@code Map} of {@code PolicyAssertion}s to corresponding 
	 * {@code PolicyAssertion.Result}s
	 */
	public Map<PolicyAssertion, Result> evaluate(String password) {
		Map<PolicyAssertion, Result> results = 
				new LinkedHashMap<PolicyAssertion, Result>();
		for (PolicyAssertion assertion : assertions)
			results.put(assertion, assertion.verify(password));
		return results;
	}
	
	/**
	 * A convenience method to get the subset which constitute a policy 
	 * violation from a {@code Map} of {@code PolicyAssertion}s to 
	 * corresponding {@code PolicyAssertion.Result}s.
	 * 
	 * @param results a {@code Map} of {@code PolicyAssertion}s and 
	 * associated {@code PolicyAssertion.Result}s to search
	 * @return the subset {@code Map} of {@code PolicyAssertion}s and 
	 * corresponding failed {@code PolicyAssertion.Result}s
	 */
	public static Map<PolicyAssertion, Result> getViolations(
			Map<PolicyAssertion, Result> results) {
		Map<PolicyAssertion, Result> violations = 
				new LinkedHashMap<PolicyAssertion, Result>();
		for (Entry<PolicyAssertion, Result> entry : results.entrySet()) {
			if (!entry.getValue().isSuccess())
				violations.put(entry.getKey(), entry.getValue());
		}
		return violations;
	}
}