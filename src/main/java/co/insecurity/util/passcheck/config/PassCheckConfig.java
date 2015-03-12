package co.insecurity.util.passcheck.config;

public final class PassCheckConfig {
	
	public static final double DEFAULT_FP_PROBABILITY = 0.001;
	public static final int DEFAULT_MIN_LENGTH = -1;
	public static final int DEFAULT_MAX_LENGTH = -1;
	public static final int DEFAULT_MAX_ITEMS = -1;
	public static final boolean DEFAULT_IGNORE_CASE = false;
	public static final String DEFAULT_DATA_FILE = "passwords.dat";

	private double fpProbability;
	private int minLength;
	private int maxLength;
	private int maxItems;
	private boolean ignoreCase;
	private String passwordDataFile;
	
	private PassCheckConfig() {
		fpProbability = DEFAULT_FP_PROBABILITY;
		minLength = DEFAULT_MIN_LENGTH;
		maxLength = DEFAULT_MAX_LENGTH;
		maxItems = DEFAULT_MAX_ITEMS;;
		ignoreCase = DEFAULT_IGNORE_CASE;
		passwordDataFile = null;
	}
	
	private PassCheckConfig(PassCheckConfig another) {
		PassCheckConfig config = new PassCheckConfig();
		config.fpProbability = another.fpProbability;
		config.ignoreCase = another.ignoreCase;
		config.maxItems = another.maxItems;
		config.minLength = another.minLength;
		config.maxLength = another.maxLength;
	}
	
	public static PassCheckConfig getConfig() {
		return new PassCheckConfig();
	}
	
	public PassCheckConfig withFalsePositiveProbability(double probability) {
		PassCheckConfig newConfig = new PassCheckConfig(this);
		newConfig.fpProbability = probability;
		return newConfig;
	}
	
	public double getFalsePositiveProbability() {
		return this.fpProbability;
	}
	
	public PassCheckConfig withMinLength(int length) {
		PassCheckConfig newConfig = new PassCheckConfig(this);
		newConfig.minLength = length;
		return newConfig;
	}
	
	public int getMinLength() {
		return this.minLength;
	}
	
	public PassCheckConfig withMaxLength(int length) {
		PassCheckConfig newConfig = new PassCheckConfig(this);
		newConfig.maxLength = length;
		return newConfig;
	}
	
	public int getMaxLength() {
		return this.maxLength;
	}
	
	public PassCheckConfig withMaxItems(int numItems) {
		PassCheckConfig newConfig = new PassCheckConfig(this);
		newConfig.maxItems = numItems;
		return newConfig;
	}
	
	public int getMaxItems() {
		return this.maxItems;
	}

	public PassCheckConfig withIgnoreCase(boolean willIgnoreCase) {
		PassCheckConfig newConfig = new PassCheckConfig(this);
		newConfig.ignoreCase= willIgnoreCase;
		return newConfig;
	}
	
	public boolean getIgnoreCase() {
		return this.ignoreCase;
	}
	
	public PassCheckConfig withPasswordDataFile(String dataFilePath) {
		PassCheckConfig newConfig = new PassCheckConfig(this);
		newConfig.passwordDataFile = dataFilePath;
		return newConfig;
	}
	
	public String getPasswordDataFile() {
		return this.passwordDataFile;
	}
}
