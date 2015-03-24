package co.insecurity.security.policy;

import java.util.LinkedHashSet;
import java.util.Set;

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
	 * @return the set of {@code PolicyAssertion.Result}s
	 */
	public Set<Result> evaluate(String password) {
		Set<Result> results = new LinkedHashSet<Result>();
		for (PolicyAssertion assertion : assertions)
			results.add(assertion.verify(password));
		return results;
	}
	
	/**
	 * A convenience method to get only the {@code PolicyAssertion.Result}s 
	 * which indicate a policy violation from a set of results.
	 * 
	 * @param results a set of {@code PolicyAssertion.Result}s to search
	 * @return the subsets of {@code Result}s raised by failed assertions
	 */
	public static Set<Result> getViolations(Set<Result> results) {
		Set<Result> violations = new LinkedHashSet<Result>();
		for (Result result : results) {
			if (!result.isSuccess())
				violations.add(result);
		}
		return violations;
	}
}