package co.insecurity.util.passcheck.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PassCheckConfig {
	
	private static final Logger LOG = LoggerFactory.getLogger(PassCheckConfig.class);

	public static final double DEFAULT_FP_PROBABILITY = 0.001;
	public static final int MIN_LENGTH_DISABLED = -1;
	public static final int DEFAULT_MIN_LENGTH = MIN_LENGTH_DISABLED;
	public static final int MAX_LENGTH_DISABLED = -1;
	public static final int DEFAULT_MAX_LENGTH = MAX_LENGTH_DISABLED;
	public static final int MAX_ITEMS_DISABLED = -1;
	public static final int DEFAULT_MAX_ITEMS = MAX_ITEMS_DISABLED;
	public static final boolean DEFAULT_IGNORE_CASE = false;
	public static final String DEFAULT_DATA_FILE = "passwords.dat";

	private double fpProbability = DEFAULT_FP_PROBABILITY;
	private int minLength = DEFAULT_MIN_LENGTH;
	private int maxLength = DEFAULT_MAX_LENGTH;
	private int maxItems = DEFAULT_MAX_ITEMS;
	private boolean ignoreCase = DEFAULT_IGNORE_CASE;
	private String passwordDataFile = null;
	
	private PassCheckConfig() {
	}
	
	public static PassCheckConfig getConfig() {
		return new PassCheckConfig();
	}
	
	public static PassCheckConfig fromOther(PassCheckConfig other) {
		LOG.debug("Copying {}", other.toString());
		PassCheckConfig newConfig = getConfig()
				.withFalsePositiveProbability(
						other.getFalsePositiveProbability())
				.withMinLength(
						other.getMinLength())
				.withMaxLength(
						other.getMaxLength())
				.withMaxItems(
						other.getMaxItems())
				.withIgnoreCase(
						other.getIgnoreCase())
				.withPasswordDataFile(
						other.getPasswordDataFile());
		LOG.debug("Copied config: {}", newConfig.toString());
		return newConfig;
	}
	
	public PassCheckConfig withFalsePositiveProbability(double probability) {
		this.fpProbability = probability;
		return this;
	}
	
	public double getFalsePositiveProbability() {
		return this.fpProbability;
	}
	
	public PassCheckConfig withMinLength(int length) {
		this.minLength = length;
		return this;
	}
	
	public int getMinLength() {
		return this.minLength;
	}
	
	public PassCheckConfig withMaxLength(int length) {
		this.maxLength = length;
		return this;
	}
	
	public int getMaxLength() {
		return this.maxLength;
	}
	
	public PassCheckConfig withMaxItems(int numItems) {
		this.maxItems = numItems;
		return this;
	}
	
	public int getMaxItems() {
		return this.maxItems;
	}

	public PassCheckConfig withIgnoreCase(boolean willIgnoreCase) {
		this.ignoreCase= willIgnoreCase;
		return this;
	}
	
	public boolean getIgnoreCase() {
		return this.ignoreCase;
	}
	
	public PassCheckConfig withPasswordDataFile(String dataFilePath) {
		this.passwordDataFile = dataFilePath;
		return this;
	}
	
	public String getPasswordDataFile() {
		return this.passwordDataFile;
	}

	@Override
	public String toString() {
		return String.format("PassCheckConfig["
				+ "fpProbability: %f, "
				+ "minLength: %d, "
				+ "maxLength: %d, "
				+ "maxItems: %d, "
				+ "ignoreCase: %b, "
				+ "passwordDataFile: %s]",
				fpProbability, minLength, maxLength, 
				maxItems, ignoreCase, passwordDataFile);
	}
}