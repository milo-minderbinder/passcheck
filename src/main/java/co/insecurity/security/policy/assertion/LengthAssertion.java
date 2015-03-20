package co.insecurity.security.policy.assertion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LengthAssertion implements PolicyAssertion {

	private static final Logger LOG = LoggerFactory.getLogger(LengthAssertion.class);

	public static final int DISABLED = -1;

	private int minLength = DISABLED;
	private int maxLength = DISABLED;
	
	public LengthAssertion() { }
	
	public LengthAssertion(int minLength, int maxLength) {
		this.minLength = minLength;
		this.maxLength = maxLength;
	}

	public int getMinLength() {
		return minLength;
	}
	
	public int getMaxLength() {
		return maxLength;
	}
	
	@Override
	public boolean isTrueFor(String password) {
		if (password == null) {
			LOG.debug("Assertion Failed - password is null");
			return false;
		}
		if ((this.minLength != LengthAssertion.DISABLED) 
				&& password.length() < this.minLength) {
			LOG.debug("Assertion Failed - did not meet minimum length: {}", 
					password);
			return false;
		}
		if ((this.maxLength != LengthAssertion.DISABLED) 
				&& password.length() > this.maxLength) {
			LOG.debug("Assertion Failed - did not meet maximum length: {}", 
					password);
			return false;
		}
		return true;
	}
}