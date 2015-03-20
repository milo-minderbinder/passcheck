package co.insecurity.security.policy;

import java.io.IOException;
import java.util.LinkedHashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.insecurity.security.policy.assertion.LengthAssertion;
import co.insecurity.security.policy.assertion.NotLeakedAssertion;
import co.insecurity.security.policy.assertion.PolicyAssertion;

public class SimplePasswordPolicy extends PasswordPolicy {
	
	private static final Logger LOG = LoggerFactory.getLogger(SimplePasswordPolicy.class);

	public SimplePasswordPolicy() {
		assertions = new LinkedHashSet<PolicyAssertion>();
		LengthAssertion length = new LengthAssertion(8, LengthAssertion.DISABLED);
		assertions.add(length);
		try {
			assertions.add(new NotLeakedAssertion
					.Builder().withFalsePositiveProbability(0.001)
					.withIgnoreCase(true)
					.build());
		} catch (IOException e) {
			LOG.error("Failed to build NotLeakedAssertion: ", e);
		}
	}
}