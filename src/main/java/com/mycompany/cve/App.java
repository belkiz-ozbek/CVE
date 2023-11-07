package com.mycompany.cve;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;


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
        final int NUMBER_CVE = 500;
        App app = new App(); // App sınıfından bir nesne oluştur
        CustomArrayList allVulnerabilities = app.new CustomArrayList();
        String firstPartOfURL = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1000&startIndex=";
        //CustomArrayList allVulnerabilities = new CustomArrayList();
        ScoreInfo[] scoreInfos = new ScoreInfo[NUMBER_CVE];

        int totalNumber = 0;
        for (int i = 0; i < 700; i = i + 1_000) {
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

    public static void QuickSort(ScoreInfo ar[], int low, int high) {
        if (low < high) {
            int temp = divide(ar, low, high);
            QuickSort(ar, low, temp - 1);
            QuickSort(ar, temp + 1, high);
        }
    }

    public static int divide(ScoreInfo ar[], int low, int high) {

        ScoreInfo pivot = ar[high];

        int i = low - 1;

        for (int j = low; j <= high; j++) {
            if (ar[j].baseScore < pivot.baseScore) {
                i++;
                ScoreInfo temp = ar[i];
                ar[i] = ar[j];
                ar[j] = temp;
            } else if (ar[j].baseScore == pivot.baseScore) {
                if (ar[j].impactScore < pivot.impactScore) {
                    i++;
                    ScoreInfo temp = ar[i];
                    ar[i] = ar[j];
                    ar[j] = temp;
                } else if (ar[j].impactScore == pivot.impactScore) {
                    if (ar[j].exploitabilityScore < pivot.exploitabilityScore) {
                        i++;
                        ScoreInfo temp = ar[i];
                        ar[i] = ar[j];
                        ar[j] = temp;
                    } else if (ar[j].exploitabilityScore == pivot.exploitabilityScore) {
                        if (ar[j].cveId.compareTo(pivot.cveId) < 0) {
                            i++;
                            ScoreInfo temp = ar[i];
                            ar[i] = ar[j];
                            ar[j] = temp;
                        }

                    }
                }
            }
        }
        ScoreInfo temp = ar[i + 1];
        ar[i + 1] = ar[high];
        ar[high] = temp;

        return i + 1;
    }
    //************************************************

    public static void mergeSort(ScoreInfo ar[], int left, int right) {
        if (left < right) {
            int middle = left + (right - left) / 2;
            mergeSort(ar, left, middle);
            mergeSort(ar, middle + 1, right);

            merging(ar, left, middle, right);
        }
    }

    public static void merging(ScoreInfo ar[], int left, int middle, int right) {
        int i, j, k;
        int size1 = middle - left + 1;
        int size2 = right - middle;

        ScoreInfo l[] = new ScoreInfo[size1];
        ScoreInfo r[] = new ScoreInfo[size2];

        for (i = 0; i < size1; i++) {
            l[i] = ar[left + i];
        }
        for (i = 0; i < size2; i++) {
            r[i] = ar[middle + 1 + i];
        }

        i = j = 0;
        k = left;

        while (i < size1 && j < size2) {
            if (l[i].baseScore > r[j].baseScore) {
                ar[k] = r[j];
                j++;
            } else {
                if (l[i].baseScore == r[j].baseScore) {
                    if (l[i].impactScore == r[j].impactScore) {
                        if (l[i].exploitabilityScore == r[j].exploitabilityScore) {
                            if (l[i].cveId.compareTo(r[j].cveId) < 0) {
                                ar[k] = l[i];
                                i++;
                            } else {
                                ar[k] = r[j];
                                j++;
                            }
                        } else if (l[i].exploitabilityScore > r[j].exploitabilityScore) {
                            ar[k] = r[j];
                            j++;
                        } else {
                            ar[k] = l[i];
                            i++;
                        }
                    } else if (l[i].impactScore > r[j].impactScore) {
                        ar[k] = r[j];
                        j++;
                    } else {
                        ar[k] = l[i];
                        i++;
                    }

                } else {
                    ar[k] = l[i];
                    i++;
                }
            }
            k++;
        }

        while (i < size1) {
            ar[k] = l[i];
            i++;
            k++;
        }
        while (j < size2) {
            ar[k] = r[j];
            j++;
            k++;
        }
    }

    //heap sort
    public static void heapSort(ScoreInfo ar[]) {
        int size = ar.length;
        for (int i = (size / 2) - 1; i >= 0; i--) {
            heap(ar, size, i);
        }

        for (int i = size - 1; i >= 0; i--) {
            ScoreInfo temp = ar[0];
            ar[0] = ar[i];
            ar[i] = temp;

            heap(ar, i, 0);
        }
    }

    public static void heap(ScoreInfo ar[], int size, int i) {
        int big = i;
        int left = 2 * i + 1;
        int right = 2 * i + 2;

        if (left < size && ar[left].baseScore > ar[big].baseScore) {
            big = left;
        }

        if (left < size && ar[left].baseScore == ar[big].baseScore) {
            if (ar[left].impactScore > ar[big].impactScore) {
                big = left;
            } else if (ar[left].impactScore == ar[big].impactScore) {
                if (ar[left].exploitabilityScore > ar[big].exploitabilityScore) {
                    big = left;
                } else if (ar[left].exploitabilityScore == ar[big].exploitabilityScore) {
                    if (ar[left].cveId.compareTo(ar[big].cveId) > 0) {
                        big = left;
                    }
                }
            }
        }

        if (right < size && ar[right].baseScore > ar[big].baseScore) {
            big = right;
        }

        if (right < size && ar[right].baseScore == ar[big].baseScore) {
            if (right < size && ar[right].impactScore > ar[big].impactScore) {
                big = right;
            } else if (right < size && ar[right].impactScore == ar[big].impactScore) {
                if (right < size && ar[right].exploitabilityScore > ar[big].exploitabilityScore) {
                    big = right;
                } else if (right < size && ar[right].exploitabilityScore == ar[big].exploitabilityScore) {
                    if (ar[right].cveId.compareTo(ar[big].cveId) > 0) {
                        big = right;
                    }
                }
            }
        }

        if (big != i) {
            ScoreInfo temp = ar[i];
            ar[i] = ar[big];
            ar[big] = temp;

            heap(ar, size, big);
        }
    }


    private static void sortScoreInfos(ScoreInfo[] scoreInfos) {


        ScoreInfo[] scoreInfosForQuickSort = Arrays.copyOf(scoreInfos, scoreInfos.length);
        ScoreInfo[] scoreInfosForMergeSort = Arrays.copyOf(scoreInfos, scoreInfos.length);
        ScoreInfo[] scoreInfosForHeapSort = Arrays.copyOf(scoreInfos, scoreInfos.length);

        ScoreInfo[] scoreInfosForInsertionSort = Arrays.copyOf(scoreInfos, scoreInfos.length);
        ScoreInfo[] scoreInfosForAvlSort = Arrays.copyOf(scoreInfos, scoreInfos.length);

        System.out.println("AVL Sort Started");
        long startTimeAvl = System.currentTimeMillis();
        AVLTree avlTree = new AVLTree();
        for (ScoreInfo scoreInfo : scoreInfosForAvlSort) {
            avlTree.insert(scoreInfo);
        }
        avlTree.inOrderTraversal();
        long endTimeAvl = System.currentTimeMillis();
        long elapsedTime = endTimeAvl - startTimeAvl;
        System.out.println("Avl sort için geçen süre: " + elapsedTime + " milisaniye");

        System.out.println("Quick Sort Started");
        long startTimeQuick = System.currentTimeMillis();
        QuickSort(scoreInfosForQuickSort, 0, scoreInfosForQuickSort.length-1);
        printResult(scoreInfosForQuickSort, "Quick Sort ");
        long endTimeQuick = System.currentTimeMillis();
        long elapsedTimeQuick = endTimeQuick - startTimeQuick;
        System.out.println("Quick sort için geçen süre: " + elapsedTimeQuick + " milisaniye");

        System.out.println("mergeSort Started");
        long startTimeMerge = System.currentTimeMillis();
        mergeSort(scoreInfosForMergeSort, 0, scoreInfos.length - 1);
        printResult(scoreInfosForMergeSort, "Merge Sort");
        long endTimeMerge = System.currentTimeMillis();
        long elapsedTimeMerge = endTimeMerge - startTimeMerge;
        System.out.println("Merge sort için geçen süre: " + elapsedTimeMerge + " milisaniye");

        System.out.println("Heap Sort Started");
        long startTimeHeap = System.currentTimeMillis();
        heapSort(scoreInfosForHeapSort);
        printResult(scoreInfosForHeapSort, "Heap Sort");
        long endTimeHeap = System.currentTimeMillis();
        long elapsedTimeHeap = endTimeHeap - startTimeHeap;
        System.out.println("Heap sort için geçen süre: " + elapsedTimeHeap + " milisaniye");

    }

    private static void printResult(ScoreInfo[] scoreInfos, String algorithm) {
        System.out.println("***************");
        System.out.println("Sorted Array, Algorithm: " + algorithm);
        for (ScoreInfo scoreInfo : scoreInfos) {
            System.out.println(scoreInfo);
        }
        System.out.println("*****************************");
        System.out.println();
        System.out.println();
    }

    private static void printScoreInfos(ScoreInfo[] scoreInfos) {
        System.out.println("Total Number of Score Info that will be sorted: " + scoreInfos.length);
        for (ScoreInfo scoreInfo : scoreInfos) {
            if (scoreInfo == null) {
                throw new RuntimeException("scoreInfos null değer içermemeli");
            }
        }
    }
}

