package co.insecurity.security.policy.assertion;

public interface PolicyAssertion {

	public boolean isTrueFor(String password);
}