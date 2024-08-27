package com.projects.auth.entity;

public enum Code {
    SUCCESS("Operaion end success");

    public final String label;
    private Code(String label){
        this.label = label;
    }
}
