package co.insecurity.security.policy.assertion;

/**
 * The {@code PolicyAssertion} interface defines a single method, 
 * {@code verify}, which takes a password string and returns a 
 * {@code PolicyAssertion.Result} indicating if the assertion is true for the 
 * given password and an explanation of why or why not.
 * 
 * @author Milo Minderbinder
 *
 */
public interface PolicyAssertion {

	/**
	 * Encapsulates the success or failure, and the corresponding reason, of 
	 * the result of testing a {@code PolicyAssertion} against a particular 
	 * password.
	 * <p>
	 * For convenience, {@code PolicyAssertion.Result} pre-defines several 
	 * static members which define common result types (e.g. generic success).
	 * 
	 * @author Milo Minderbinder
	 *
	 */
	public class Result {
		/**
		 * A generic successful result.
		 */
		public static final Result SUCCESS = 
				new Result(true, "Password meets assertion criteria.");
		/**
		 * A failing result due to a null password.
		 */
		public static final Result NULL_VALUE = 
				new Result(false, "Supplied password value is null.");

		private final boolean success;
		private final String reason;
		
		/**
		 * Instantiates a new {@code PolicyAssertion.Result}.
		 * 
		 * @param success indicates whether the {@code PolicyAssertion} 
		 * successfully held for a call to {@code verify()}
		 * @param reason the cause or explanation for the {@code Result}
		 */
		public Result(boolean success, String reason) {
			this.success = success;
			this.reason = reason;
		}
		
		/**
		 * Indicates if the {@code PolicyAssertion} successfully held for a 
		 * password tested in a call to {@code verify()}.
		 * 
		 * @return true if the corresponding assertion held, otherwise 
		 * returns false if this {@code Result} represents a failed assertion
		 */
		public boolean isSuccess() { return success; }
		
		/**
		 * Provides an explanation for the success or failure of this 
		 * {@code PolicyAssertion.Result}.
		 * 
		 * @return an explanation of the success or failure 
		 */
		public String getReason() { return reason; }
	}
	
	/**
	 * Implementations must return a {@code PolicyAssertion.Result} indicating 
	 * whether or not the specified password meets the assertion criteria and 
	 * providing an accompanying explanation.
	 * <p>
	 * As an example, a {@code PolicyAssertion} might implement the 
	 * {@code verify} method to test the assertion that the supplied password 
	 * is at least 10 characters long and contains a digit.
	 * 
	 * @param password the password to verify against the assertion definition
	 * @return a {@code PolicyAssertion.Result} indicating whether the 
	 * assertion is met
	 */
	public Result verify(String password);
}