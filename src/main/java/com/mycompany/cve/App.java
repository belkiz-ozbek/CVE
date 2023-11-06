
package com.mycompany.cve;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;


public class App {


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
        final int NUMBER_CVE = 100;
        App app = new App(); // App sınıfından bir nesne oluştur
        CustomArrayList allVulnerabilities = app.new CustomArrayList();
        String firstPartOfURL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1000&startIndex=";
        //CustomArrayList allVulnerabilities = new CustomArrayList();
        ScoreInfo[] scoreInfos = new ScoreInfo[NUMBER_CVE];

        int totalNumber = 0;
        for (int i = 0; i < 200; i = i + 1_000) {
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
                    if (vulnerability.cve.metrics.cvssMetricV2 != null) {

                        String cveId = vulnerability.cve.id;
                        double baseScore = vulnerability.cve.metrics.cvssMetricV2.get(0).cvssData.baseScore;
                        double impactScore = vulnerability.cve.metrics.cvssMetricV2.get(0).impactScore;
                        double exploitabilityScore = vulnerability.cve.metrics.cvssMetricV2.get(0).exploitabilityScore;
                        // System.out.println(String.format("CVE-ID:%s \t Base Score: %f  \t impact Score %f \t exploitability Score %f",cveId, baseScore, impactScore, exploitabilityScore));
                        if (totalNumber < NUMBER_CVE) {
                            scoreInfos[totalNumber] = new ScoreInfo(cveId, baseScore, impactScore, exploitabilityScore);
                        }
                        totalNumber++;

                    } else {
                        //System.out.println("baseScore is null");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("total Numbers : " + totalNumber);
        }

        printScoreInfos(scoreInfos);
        sortScoreInfos(scoreInfos);
        //System.out.println("lshdfadsbcjlasbcjbsdljc" + scoreInfos[0].baseScore);

    }

     public void QuickSort(ScoreInfo ar[], int low, int high){
        if(low<high){
            int temp = divide(ar, low, high);
            QuickSort(ar, low, temp-1);
            QuickSort(ar, temp+1, high);
        }
    }
    public int divide(ScoreInfo ar[], int low, int high){
        
        ScoreInfo pivot=ar[high];
        
        int i= low-1;
        
        for(int j=low; j<=high; j++){
            if(ar[j].baseScore < pivot.baseScore){
                i++;
                ScoreInfo temp= ar[i];
                ar[i]=ar[j];
                ar[j]=temp;
            }
            else if(ar[j].baseScore == pivot.baseScore){
                if(ar[j].impactScore < pivot.impactScore){
                    i++;
                    ScoreInfo temp= ar[i];
                    ar[i]=ar[j];
                    ar[j]=temp;
                }
                else if(ar[j].impactScore == pivot.impactScore){
                    if(ar[j].exploitabilityScore < pivot.exploitabilityScore){
                        i++;
                        ScoreInfo temp= ar[i];
                        ar[i]=ar[j];
                        ar[j]=temp;
                    }
                    else if(ar[j].exploitabilityScore == pivot.exploitabilityScore){
                        if(ar[j].cveId.compareTo(pivot.cveId)<0){
                            i++;
                            ScoreInfo temp= ar[i];
                            ar[i]=ar[j];
                            ar[j]=temp;
                        }
                        
                    }
                }
            }
        }
        ScoreInfo temp=ar[i+1];
        ar[i+1]=ar[high];
        ar[high]=temp;
        
        return i+1;
    }
    

    private static void sortScoreInfos(ScoreInfo[] scoreInfos) {

        System.out.println("QuickSort Started");

        int low = 0;
        int high = scoreInfos.length - 1;
        QuickSort(scoreInfos, low, high);
        System.out.println("QuickSort finished");
        System.out.println("***************");
        System.out.println("***************");
        System.out.println("***************");
        System.out.println("Sorted Another Array:");
        for (ScoreInfo scoreInfo : scoreInfos) {
            System.out.println(scoreInfo);
        }
    }

    private static void printScoreInfos(ScoreInfo[] scoreInfos) {
        System.out.println("Total Number of Score Info that will be sorted: " + scoreInfos.length);
//        for (ScoreInfo scoreInfo : scoreInfos) {
//            System.out.println(scoreInfo);
//        }
    }
}
    
    

