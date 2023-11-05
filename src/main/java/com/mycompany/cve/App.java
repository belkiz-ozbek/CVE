
package com.mycompany.cve;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.mycompany.cve.Configuration;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import com.fasterxml.jackson.databind.ObjectMapper;


public class App{

    
    class CustomArrayList {
        private String[] elements;
        private int size;
        private static final int DEFAULT_CAPACITY = 10;

        public CustomArrayList() {
            this.elements = new String[DEFAULT_CAPACITY];
            this.size = 0;
        }

        public void add(String element) {
            if (size == elements.length) {
                ensureCapacity();
            }
            elements[size++] = element;
        }

        public String get(int index) {
            if (index < 0 || index >= size) {
                throw new IndexOutOfBoundsException("Invalid index");
            }
            return elements[index];
        }

        public int size() {
            return size;
        }

        private void ensureCapacity() {
            int newCapacity = elements.length * 2;
            String[] newElements = new String[newCapacity];
            System.arraycopy(elements, 0, newElements, 0, size);
            elements = newElements;
        }

        public void addAll(Vulnerability[] vulnerabilities) {
            for (Vulnerability vulnerability : vulnerabilities) {
                add(vulnerability.toString()); // toString metodunu Vulnerability sınıfına uygulamanız gerekmektedir
            }
        }
    }

     public static String getJsonFromUrl(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String inputLine;

        while ((inputLine = reader.readLine()) != null) {
            response.append(inputLine);
        }

        reader.close();
        return response.toString();
    }

    public static String getJsonFromUrlWithRetry(String urlString, int maxRetries) throws Exception {
        for (int retry = 0; retry <= maxRetries; retry++) {
            try {
                URL url = new URL(urlString);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");

                int responseCode = connection.getResponseCode();

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String inputLine;

                    while ((inputLine = reader.readLine()) != null) {
                        response.append(inputLine);
                    }

                    reader.close();
                    return response.toString();
                } else {
                    // If the response is not successful, you can choose to log or handle the error here.
                    System.out.println("Request failed with response code: " + responseCode);
                }
            } catch (IOException e) {
                // Handle exceptions, such as network issues, here if needed.
                e.printStackTrace();
            }

            if (retry < maxRetries) {
                // If the request was not successful and we have retries left, wait for a while before retrying.
                int retryDelaySeconds = 5; // You can adjust the retry delay as needed.
                System.out.println("Retrying in " + retryDelaySeconds + " seconds...");
                Thread.sleep(retryDelaySeconds * 1000);
            }
        }

        // If all retries fail, you can throw an exception or return an appropriate error message.
        throw new Exception("Failed to fetch data after " + maxRetries + " retries.");
    }


    public static void main(String[] args) {
             App app = new App(); // App sınıfından bir nesne oluştur
            CustomArrayList allVulnerabilities = app.new CustomArrayList();
        String firstPartOfURL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1000&startIndex=";
        //CustomArrayList allVulnerabilities = new CustomArrayList();

             int totalNumber = 0;
        for (int i =0; i < 50_000; i = i + 1_000) {
            String completeURL = firstPartOfURL + i;
            try {
                //String json = getJsonFromUrl(completeURL); // URL adresini buraya ekleyin
                String json = getJsonFromUrlWithRetry(completeURL, 100); // URL adresini buraya ekleyin
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                // JSON verisini Java nesnesine dönüştürme
                Root root = objectMapper.readValue(json, Root.class);

                // Elde edilen vulnerabilities listesini allVulnerabilities listesine ekleyin
                allVulnerabilities.addAll(root.vulnerabilities.toArray(new Vulnerability[0]));
                 for (Vulnerability vulnerability : root.vulnerabilities) {
                     if (vulnerability.cve.metrics.cvssMetricV2 != null ){
                         double baseScore = vulnerability.cve.metrics.cvssMetricV2.get(0).cvssData.baseScore;
                         System.out.println("Base Score: " + baseScore);
                         totalNumber++;

                     }else {
                         System.out.println("baseScore is null");
                     }
                                                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("total Numbers : " +totalNumber);
        }
    }
}
    
    

