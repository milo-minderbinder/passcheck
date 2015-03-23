package co.insecurity.security.policy.assertion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@code PolicyAssertion} that defines a minimum and/or maximum length 
 * requirement for a {@code PasswordPolicy}.
 * 
 * @author Milo Minderbinder 
 *
 */
public class LengthAssertion implements PolicyAssertion {

	private static final Logger LOG = LoggerFactory.getLogger(LengthAssertion.class);
	
	public static final int DISABLED = -1;
	/**
	 * A {@code PolicyAssertion.Result} indicating a password was too short
	 */
	public static final Result INSUFFICIENT_LENGTH =
			new Result(false, "Password does not meet minimum length requirement.");
	/**
	 * A {@code PolicyAssertion.Result} indicating a password was too long 
	 */
	public static final Result EXCESSIVE_LENGTH = 
			new Result(false, "Password exceeds the maximum length requirement.");
	
	private int minLength = DISABLED;
	private int maxLength = DISABLED;
	
	/**
	 * Constructs a {@code LengthAssertion} that does not require either a 
	 * minimum or a maximum password length.
	 */
	public LengthAssertion() { }
	
	/**
	 * Constructs a {@code LengthAssertion} that requires passwords to meet 
	 * the given minimum and maximum length requirements.
	 * 
	 * Each value should be set to either a positive integer, or to 
	 * {@code LengthAssertion.DISABLED}, which will disable that length 
	 * requirement. For example, a {@code LengthAssertion} constructed with 
	 * {@code LengthAssertion(8, LengthAssertion.DISABLED)} will assert that 
	 * passwords are 8 or more characters in length, with no upper-limit to 
	 * the length (e.g. may have 8 or 800 characters, but not 7).
	 * 
	 * @param minLength the minimum password length required by the assertion
	 * @param maxLength the maximum password length required by the assertion
	 */
	public LengthAssertion(int minLength, int maxLength) {
		this.minLength = minLength;
		this.maxLength = maxLength;
	}

	/**
	 * Returns the minimum number of characters that a password must have in 
	 * order to pass the policy assertion.
	 * 
	 * @return the minimum number of characters required or 
	 * {@code LengthAssertion.Disabled} if no minimum length is defined
	 */
	public int getMinLength() {
		return minLength;
	}
	
	/**
	 * Returns the maximum number of characters that a password may have in 
	 * order to pass the policy assertion.
	 * 
	 * @return the maximum number of characters required or 
	 * {@code LengthAssertion.Disabled} if no maximum length is defined
	 */
	public int getMaxLength() {
		return maxLength;
	}
	
	/**
	 * Indicates whether the given password meets the length requirements 
	 * defined by this {@code LengthAssertion}.
	 * 
	 * A password will return a failing {@code PolicyAssertion.Result} if the 
	 * password is null or if it does not meet the minimum or maximum length 
	 * requirements.
	 * 
	 * @return a failing {@code Result} if the password is null or does not 
	 * meet the minimum or maximum length requirement, otherwise returns a 
	 * generic success {@code Result}
	 */
	@Override
	public Result verify(String password) {
		if (password == null) {
			LOG.debug("Assertion Failed - password is null");
			return Result.NULL_VALUE;
		}
		if ((this.minLength != LengthAssertion.DISABLED) 
				&& password.length() < this.minLength) {
			LOG.debug("Assertion Failed - did not meet minimum length: {}", 
					password);
			return INSUFFICIENT_LENGTH;
		}
		if ((this.maxLength != LengthAssertion.DISABLED) 
				&& password.length() > this.maxLength) {
			LOG.debug("Assertion Failed - did not meet maximum length: {}", 
					password);
			return EXCESSIVE_LENGTH;
		}
		return Result.SUCCESS;
	}
}