package co.insecurity.util.passcheck;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import co.insecurity.util.BloomFilter;

public class PassCheck {

	private static final Logger LOG = LoggerFactory.getLogger(PassCheck.class);
	
	private double fpProbability;
	private int numExpectedElements;
	private BloomFilter<String> filter;
	private Properties properties;
	
	
	public PassCheck() throws IOException {
		properties = loadProperties();
		ArrayList<String> pwList = loadPasswords(properties.getProperty("datafile"));
		fpProbability = Double.parseDouble(
				properties.getProperty("falsePositiveProbability"));
		numExpectedElements = pwList.size();
		LOG.info("Creating BloomFilter with falsePositiveProbability={} and expectedNumberOfElements={}", 
				fpProbability, numExpectedElements);
		filter = new BloomFilter<String>(fpProbability, numExpectedElements);
		LOG.debug("Adding {} passwords to filter...", pwList.size());
		filter.addAll(pwList);
	}
	
	private Properties loadProperties() throws IOException {
		Properties props = new Properties();
		props.load(PassCheck.class.
				getClassLoader().getResourceAsStream("passcheck.properties"));
		return props;
	}
	
	private ArrayList<String> loadPasswords(String fileName) {
		LOG.info("Loading passwords from file: {}", fileName);
		ArrayList<String> passwords = new ArrayList<String>();
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(
				PassCheck.class.getClassLoader().getResourceAsStream(fileName)))){
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] item = line.split("\t");
				passwords.add(item[0]);
			}
		} catch (IOException e) {
			e.printStackTrace();
			LOG.error("Error while reading data file: {}", fileName);
			return null;
		}
		return passwords;
	}
	
	public boolean isCommon(String password) {
		if (filter.contains(password)) {
			LOG.debug("Found password in filter: {}", password);
			return true;
		}
		else {
			LOG.debug("Did not find password in filter: {}", password);
			return false;
		}
	}
}