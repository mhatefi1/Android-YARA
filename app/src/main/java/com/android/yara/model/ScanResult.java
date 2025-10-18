package com.android.yara.model;

import androidx.annotation.Nullable;

import java.io.Serializable;

public class ScanResult implements Serializable {

    @Nullable
    public String ruleName;

    @Nullable
    public String detail;

    @Nullable
    public String target;

    @Nullable
    public String packageName;

    @Nullable
    public String fileUriString;

    @Nullable
    public String filePath;

    public boolean isSafe = false;

    public static ScanResult safeRow(String scopeSummary) {
        ScanResult s = new ScanResult();
        s.isSafe = true;
        s.ruleName = "Clean — no threats found";
        s.detail = scopeSummary;
        s.target = "";
        return s;
    }
}