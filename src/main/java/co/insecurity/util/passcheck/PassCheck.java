package co.insecurity.util.passcheck;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.insecurity.util.BloomFilter;

public class PassCheck {

	private static final Logger LOG = LoggerFactory.getLogger(PassCheck.class);
	private static final String DEFAULT_DATA_FILE = "passcheck.dat";
	private static final String DEFAULT_FP_PROBABILITY = "0.001";
	
	private Path customDataFile;
	private double fpProbability;
	private int minLength;
	private int maxLength;
	private int maxSize;
	private boolean ignoreCase;
	private BloomFilter<String> filter;
	
	
	public PassCheck() {
		loadConfig();
		filter = createFilter();
	}
	
	private void loadConfig() {
		Properties props = new Properties();
		try {
			props.load(PassCheck.class.
					getClassLoader().getResourceAsStream("passcheck.properties"));
		} catch (IOException e) {
			LOG.error("Could not load configuration properties from passcheck.properties");
			LOG.debug(e.getMessage());
		}

		fpProbability = Double.parseDouble(
				props.getProperty("falsePositiveProbability", DEFAULT_FP_PROBABILITY));
		
		if (props.containsKey("datafile")) {
			String dataFile = props.getProperty("datafile");
			Path dataFilePath = Paths.get(dataFile);
			if (dataFilePath.toFile().isFile()) {
				LOG.info("Using custom PassCheck data file: {}", 
						dataFilePath.toAbsolutePath());
				customDataFile = dataFilePath;
			}
			else {
				LOG.warn("Using default PassCheck data file, unable to locate custom file: {}",
						dataFile);
				customDataFile = null;
			}
		} else {
			LOG.info("Using default PassCheck data file");
			customDataFile = null;
		}
		
		minLength = Integer.parseInt(props.getProperty("minPasswordLength", "-1"));
		maxLength = Integer.parseInt(props.getProperty("maxPasswordLength", "-1"));
		maxSize = Integer.parseInt(props.getProperty("maxNumPasswords", "-1"));
		ignoreCase = Boolean.parseBoolean(props.getProperty("ignoreCase", "false"));
	}
	
	private TreeSet<String> loadPasswordData() {
		TreeSet<String> passwordSet = new TreeSet<String>();
		int numAdded = 0;
		BufferedReader reader;
		try {
			if (customDataFile != null) {
				LOG.info("Loading password data from custom data file: {}", customDataFile.toAbsolutePath());
				reader = Files.newBufferedReader(customDataFile, Charset.forName("ISO-8859-1"));
			}
			else {
				LOG.info("Loading password data from default data file");
				reader = new BufferedReader(new InputStreamReader(
						PassCheck.class.getClassLoader().getResourceAsStream(DEFAULT_DATA_FILE)));
			}
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] item = line.split("\t");
				if ((minLength != -1) && (minLength > Integer.parseInt(item[2])))
					continue;
				if ((maxLength != -1) && (maxLength < Integer.parseInt(item[2])))
					continue;
				if ((maxSize != -1) && (numAdded++ >= maxSize))
					return passwordSet;
				if (ignoreCase)
					passwordSet.add(item[0].toLowerCase());
				else
					passwordSet.add(item[0]);
				passwordSet.add(item[0]);
			}
		} catch (IOException e) {
			e.printStackTrace();
			LOG.error("Error while processing data file");
			return null;
		}
		return passwordSet;
	}
	
	private BloomFilter<String> createFilter() {
		TreeSet<String> passwordSet = loadPasswordData();
		LOG.info("Creating BloomFilter with falsePositiveProbability={} and expectedNumberOfElements={}", 
				fpProbability, passwordSet.size());
		filter = new BloomFilter<String>(fpProbability, passwordSet.size());
		
		LOG.debug("Adding {} passwords to filter...", passwordSet.size());
		filter.addAll(passwordSet);

		return filter;
	}
	
	public boolean isCommon(String password) {
		if (ignoreCase)
			password = password.toLowerCase();
		
		if ((minLength != -1) && password.length() < minLength) {
			LOG.debug("Password did not meet minimum length requirements: {}", password);
			return false;
		}
		if ((maxLength != -1) && password.length() > maxLength) {
			LOG.debug("Password did not meet maximum length requirements: {}", password);
			return false;
		}
		if (filter.contains(password)) {
			LOG.debug("Found password in filter: {}", password);
			return true;
		}
		else {
			LOG.debug("Did not find password in filter: {}", password);
			return false;
		}
	}
	
	public static void main(String[] args) {
		PassCheck pc = new PassCheck();
		pc.isCommon("password");
		pc.isCommon("dog");
		pc.isCommon("oibeinvniciapifgpiupioufvjkpausepioupiofv8994t8hbv");
	}
}