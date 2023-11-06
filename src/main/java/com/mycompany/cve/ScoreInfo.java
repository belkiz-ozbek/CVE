package com.mycompany.cve;
public class ScoreInfo implements Comparable<ScoreInfo> {
    public String cveId;
    public double baseScore;
    public double impactScore;
    public double exploitabilityScore;

    public ScoreInfo(String cveId, double baseScore, double impactScore, double exploitabilityScore) {
        this.cveId = cveId;
        this.baseScore = baseScore;
        this.impactScore = impactScore;
        this.exploitabilityScore = exploitabilityScore;
    }

    @Override
    public int compareTo(ScoreInfo other) {
        if (this.baseScore > other.baseScore) {
            return -1; // Büyük baseScore daha yüksek öncelik
        } else if (this.baseScore < other.baseScore) {
            return 1; // Diğer durumda, büyük baseScore daha düşük öncelik
        } else {
            // baseScore eşit, impactScore karşılaştırılır
            if (this.impactScore > other.impactScore) {
                return -1; // Büyük impactScore daha yüksek öncelik
            } else if (this.impactScore < other.impactScore) {
                return 1; // Diğer durumda, büyük impactScore daha düşük öncelik
            } else {
                // baseScore ve impactScore eşit, exploitabilityScore karşılaştırılır
                if (this.exploitabilityScore > other.exploitabilityScore) {
                    return -1; // Büyük exploitabilityScore daha yüksek öncelik
                } else if (this.exploitabilityScore < other.exploitabilityScore) {
                    return 1; // Diğer durumda, büyük exploitabilityScore daha düşük öncelik
                } else {
                    // Tüm puanlar eşit, daha düşük CVE-ID önceliğe sahiptir.
                    return this.cveId.compareTo(other.cveId);
                }
            }
        }
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
                }
            }
        }
        ScoreInfo temp=ar[i+1];
        ar[i+1]=ar[high];
        ar[high]=temp;

        return i+1;
    }

    @Override
    public String toString() {
        return "ScoreInfo{" +
                "cveId='" + cveId + '\'' +
                ", baseScore=" + baseScore +
                ", impactScore=" + impactScore +
                ", exploitabilityScore=" + exploitabilityScore +
                '}';
    }
}
