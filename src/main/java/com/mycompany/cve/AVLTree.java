package com.mycompany.cve;

public class AVLTree {
    AVLNode root;

    int height(AVLNode node) {
        if (node == null) {
            return 0;
        }
        return node.height;
    }

    int getBalance(AVLNode node) {
        if (node == null) {
            return 0;
        }
        return height(node.left) - height(node.right);
    }

    AVLNode rightRotate(AVLNode y) {
        AVLNode x = y.left;
        AVLNode T2 = x.right;

        x.right = y;
        y.left = T2;

        y.height = Math.max(height(y.left), height(y.right)) + 1;
        x.height = Math.max(height(x.left), height(x.right)) + 1;

        return x;
    }

    AVLNode leftRotate(AVLNode x) {
        AVLNode y = x.right;
        AVLNode T2 = y.left;

        y.left = x;
        x.right = T2;

        x.height = Math.max(height(x.left), height(x.right)) + 1;
        y.height = Math.max(height(y.left), height(y.right)) + 1;

        return y;
    }

    AVLNode insert(AVLNode node, ScoreInfo data) {
        if (node == null) {
            return new AVLNode(data);
        }

        if (data.compareTo(node.data) < 0) {
            node.left = insert(node.left, data);
        } else if (data.compareTo(node.data) > 0) {
            node.right = insert(node.right, data);
        } else {
            return node;
        }

        node.height = 1 + Math.max(height(node.left), height(node.right));

        int balance = getBalance(node);

        if (balance > 1 && data.compareTo(node.left.data) < 0) {
            return rightRotate(node);
        }
        if (balance < -1 && data.compareTo(node.right.data) > 0) {
            return leftRotate(node);
        }
        if (balance > 1 && data.compareTo(node.left.data) > 0) {
            node.left = leftRotate(node.left);
            return rightRotate(node);
        }
        if (balance < -1 && data.compareTo(node.right.data) < 0) {
            node.right = rightRotate(node.right);
            return leftRotate(node);
        }

        return node;
    }

    void insert(ScoreInfo data) {
        root = insert(root, data);
    }

    void inOrderTraversal(AVLNode node) {
        if (node != null) {
            inOrderTraversal(node.left);
            System.out.println(node.data);
            inOrderTraversal(node.right);
        }
    }

    void postOrderTraversal(AVLNode node) {
        if (node != null) {
            postOrderTraversal(node.left);
            postOrderTraversal(node.right);
            System.out.println(node.data);
        }
    }

    void inOrderTraversal() {
        inOrderTraversal(root);
    }

    void printSorted() {
        inOrderTraversal();
    }
}

class AVLNode {
    ScoreInfo data;
    AVLNode left;
    AVLNode right;
    int height;

    AVLNode(ScoreInfo data) {
        this.data = data;
        this.left = null;
        this.right = null;
        this.height = 1;
    }
}

