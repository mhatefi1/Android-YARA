package com.android.yara;

import android.app.Activity;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ClipData;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import androidx.documentfile.provider.DocumentFile;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.transition.AutoTransition;
import androidx.transition.Transition;
import androidx.transition.TransitionManager;

import com.android.yara.adapter.ScanResultAdapter;
import com.android.yara.model.ScanResult;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Queue;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import io.reactivex.Observable;
import io.reactivex.Single;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.schedulers.Schedulers;

public class YaraScanActivity extends AppCompatActivity {

    public native List<String> runYARA(List<String> rules, String path, @Nullable byte[] data, long size);

    public native void destroyYARA();

    public native String getYARAVersion();

    static {
        System.loadLibrary("yara");
    }

    private ActivityResultLauncher<Intent> pickRulesLauncher;
    private ActivityResultLauncher<Intent> pickFileLauncher;
    private ActivityResultLauncher<Intent> pickDirLauncher;
    private ActivityResultLauncher<Intent> uninstallLauncher;

    private MaterialButton btnStartScan, btnSelectRules, btnChooseFile, btnChooseFolder;
    private LinearProgressIndicator progressBar;
    private ChipGroup chipGroupRules;
    private Chip chipSelectedFile;
    private TextView tvProgress;
    private RadioButton rbSingleFile, rbInstalledApps;
    private View rowFilePicker;
    private MaterialCardView cardResults;
    private TextView tvResultsTitle;
    private ImageView ivResultsToggle;
    private RecyclerView rvResults;
    private boolean resultsExpanded = true;

    private ScanResultAdapter resultAdapter;

    private final ArrayList<String> rulesList = new ArrayList<>();
    private boolean compiled = false;
    @Nullable
    private Uri singleFileUri = null;
    @Nullable
    private Uri selectedDirUri = null;

    private final ArrayList<ScanResult> results = new ArrayList<>();
    private final CompositeDisposable disposables = new CompositeDisposable();
    private boolean isScanning = false;
    private static final int CHUNK_SIZE = 5 * 1024 * 1024;

    @Nullable
    private String pendingUninstallPackage = null;

    long start;
    private static final String CHANNEL_ID = "yara_scan_channel";
    private static final int NOTIFICATION_ID = 1001;
    private NotificationManager notificationManager;
    private ActivityResultLauncher<String> requestPermissionLauncher;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_yara_scan);

        registerLaunchers();

        TextView tvScreenSubtitle = findViewById(R.id.tvScreenSubtitle);
        btnSelectRules = findViewById(R.id.btnSelectRules);
        btnChooseFile = findViewById(R.id.btnChooseFile);
        btnChooseFolder = findViewById(R.id.btnChooseFolder);
        btnStartScan = findViewById(R.id.btnStartScan);
        tvProgress = findViewById(R.id.tvProgress);
        progressBar = findViewById(R.id.progressScan);
        chipGroupRules = findViewById(R.id.chipGroupRules);
        chipSelectedFile = findViewById(R.id.chipSelectedFile);
        RadioGroup rgTarget = findViewById(R.id.rgTarget);
        rbInstalledApps = findViewById(R.id.rbInstalledApps);
        rbSingleFile = findViewById(R.id.rbSingleFile);
        rowFilePicker = findViewById(R.id.rowFilePicker);

        cardResults = findViewById(R.id.cardResults);
        tvResultsTitle = findViewById(R.id.tvResultsTitle);
        ivResultsToggle = findViewById(R.id.ivResultsToggle);
        rvResults = findViewById(R.id.rvResults);

        notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        createNotificationChannel();

        requestPermissionLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestPermission(),
                isGranted -> {
                    if (isGranted) {
                        maybeStartScan();
                    } else {
                        Toast.makeText(this, "Notifications disabled. Scan will run without them.", Toast.LENGTH_SHORT).show();
                        maybeStartScan();
                    }
                }
        );

        tvScreenSubtitle.setText(getString(R.string.description, getYARAVersion()));

        chipSelectedFile.setOnCloseIconClickListener(v -> {
            chipSelectedFile.setVisibility(View.GONE);
            singleFileUri = null;
            selectedDirUri = null;
        });

        resultAdapter = new ScanResultAdapter(results);
        resultAdapter.setOnActionListener(this::onDeleteRequested);
        rvResults.setLayoutManager(new LinearLayoutManager(this));
        rvResults.setAdapter(resultAdapter);
        rvResults.setNestedScrollingEnabled(false);
        rvResults.setOverScrollMode(View.OVER_SCROLL_NEVER);

        // Expand/collapse results with a smooth transition
        findViewById(R.id.resultsHeaderRow).setOnClickListener(v -> {
            resultsExpanded = !resultsExpanded;
            updateResultsExpansion(true);
        });

        btnSelectRules.setOnClickListener(v -> pickRules());
        btnChooseFile.setOnClickListener(v -> pickSingleFile());
        btnChooseFolder.setOnClickListener(v -> pickFolder());
        btnStartScan.setOnClickListener(v -> maybeStartScan());

        rgTarget.setOnCheckedChangeListener((g, id) -> {
            boolean single = (id == R.id.rbSingleFile);

            if (single && rowFilePicker.getVisibility() != View.VISIBLE) {
                float dp = getResources().getDisplayMetrics().density;
                rowFilePicker.setAlpha(0f);
                rowFilePicker.setTranslationY(8f * dp);
                rowFilePicker.setVisibility(View.VISIBLE);
                rowFilePicker.animate()
                        .alpha(1f)
                        .translationY(0f)
                        .setDuration(150)
                        .start();
            } else if (!single && rowFilePicker.getVisibility() == View.VISIBLE) {
                float dp = getResources().getDisplayMetrics().density;
                rowFilePicker.animate()
                        .alpha(0f)
                        .translationY(8f * dp)
                        .setDuration(150)
                        .withEndAction(() -> {
                            rowFilePicker.setVisibility(View.GONE);
                            rowFilePicker.setAlpha(1f);
                            rowFilePicker.setTranslationY(0f);
                        })
                        .start();

                chipSelectedFile.setVisibility(View.GONE);
                singleFileUri = null;
                selectedDirUri = null;
            }
        });

        tvProgress.setText("");
        tvProgress.setVisibility(View.GONE);
        progressBar.setVisibility(View.GONE);
        progressBar.setIndeterminate(false);
        progressBar.setMax(100);
        progressBar.setProgress(0);
        cardResults.setVisibility(View.GONE);
        updateRulesChips();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        disposables.clear();
        cancelNotification();
        deleteRulesCacheDir();
        try {
            destroyYARA();
        } catch (Throwable ignore) {
        }
    }


    private void updateNotification(String title, int progress, int max, boolean indeterminate) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                return;
            }
        }

        Intent intent = new Intent(this, YaraScanActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("YARA Scanner")
                .setContentText(title)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOnlyAlertOnce(true)
                .setOngoing(true)
                .setContentIntent(pendingIntent)
                .setProgress(max, progress, indeterminate);

        notificationManager.notify(NOTIFICATION_ID, builder.build());
    }

    private void cancelNotification() {
        notificationManager.cancel(NOTIFICATION_ID);
    }

    private void showCompleteNotification(int detections) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        Intent intent = new Intent(this, YaraScanActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);

        String msg = detections > 0 ? "Scan complete. Found " + detections + " threats." : "Scan complete. No threats found.";

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("Scan Finished")
                .setContentText(msg)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setOngoing(false)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent);

        notificationManager.notify(NOTIFICATION_ID, builder.build());
    }

    private void createNotificationChannel() {
        CharSequence name = "YARA Scan Progress";
        String description = "Shows progress of active YARA scans";
        int importance = NotificationManager.IMPORTANCE_LOW;
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
        channel.setDescription(description);
        notificationManager.createNotificationChannel(channel);
    }

    private void registerLaunchers() {
        pickRulesLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                (ActivityResult result) -> {
                    if (result.getResultCode() != Activity.RESULT_OK || result.getData() == null)
                        return;
                    ArrayList<Uri> picked = getUris(result);
                    disposables.add(
                            Single.fromCallable(() -> {
                                        try {
                                            return cacheRuleFilesAndComputeCompiled(picked);
                                        } finally {
                                            try {
                                                destroyYARA();
                                            } catch (Throwable ignore) {
                                            }
                                        }
                                    })
                                    .subscribeOn(Schedulers.io())
                                    .observeOn(AndroidSchedulers.mainThread())
                                    .subscribe(res -> {
                                        rulesList.clear();
                                        rulesList.addAll(res.paths);
                                        compiled = res.anyCompiled;
                                        updateRulesChips();
                                    }, err -> Toast.makeText(this, "Failed to read rules: " + err.getMessage(), Toast.LENGTH_LONG).show())
                    );
                });

        pickFileLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                (ActivityResult result) -> {
                    if (result.getResultCode() != Activity.RESULT_OK || result.getData() == null)
                        return;
                    Uri u = result.getData().getData();
                    int takeFlags = result.getData().getFlags()
                            & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                    if (takeFlags == 0)
                        takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
                    try {
                        if (u != null)
                            getContentResolver().takePersistableUriPermission(u, takeFlags);
                    } catch (Exception ignore) {
                    }

                    String pretty = readableName(u);
                    chipSelectedFile.setText(pretty);
                    chipSelectedFile.setVisibility(View.VISIBLE);
                    selectedDirUri = null;
                    singleFileUri = u;
                });

        pickDirLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                (ActivityResult result) -> {
                    if (result.getResultCode() != Activity.RESULT_OK || result.getData() == null)
                        return;
                    Uri treeUri = result.getData().getData();
                    if (treeUri != null) {
                        int takeFlags = result.getData().getFlags()
                                & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                        if (takeFlags == 0)
                            takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
                        try {
                            getContentResolver().takePersistableUriPermission(treeUri, takeFlags);
                        } catch (Exception ignore) {
                        }

                        selectedDirUri = treeUri;
                        singleFileUri = null;
                        String label = "Folder: " + (DocumentFile.fromTreeUri(this, treeUri) != null
                                ? Objects.requireNonNull(DocumentFile.fromTreeUri(this, treeUri)).getName()
                                : readableName(treeUri));
                        chipSelectedFile.setText(label);
                        chipSelectedFile.setVisibility(View.VISIBLE);
                    }
                });

        uninstallLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                (ActivityResult result) -> {
                    if (pendingUninstallPackage == null) return;
                    boolean removed = !isPackageInstalled(pendingUninstallPackage);
                    if (removed) {
                        removeRowsForPackage(pendingUninstallPackage);
                        Toast.makeText(this, "App uninstalled.", Toast.LENGTH_SHORT).show();
                        updateResultsCardVisibility(); // <-- refresh title/count/visibility
                    } else {
                        Toast.makeText(this, "Uninstall canceled.", Toast.LENGTH_SHORT).show();
                    }
                    pendingUninstallPackage = null;
                });

    }

    @NonNull
    private static ArrayList<Uri> getUris(ActivityResult result) {
        Intent data = result.getData();
        ArrayList<Uri> picked = new ArrayList<>();
        ClipData clip = (data != null) ? data.getClipData() : null;
        if (clip != null) {
            for (int i = 0; i < clip.getItemCount(); i++) {
                Uri u = clip.getItemAt(i).getUri();
                if (u != null) picked.add(u);
            }
        } else if (data != null) {
            Uri u = data.getData();
            if (u != null) picked.add(u);
        }
        return picked;
    }

    private void pickRules() {
        Intent i = new Intent(Intent.ACTION_GET_CONTENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        pickRulesLauncher.launch(Intent.createChooser(i, "Select YARA rules (.yar / .yarac)"));
    }

    private void pickSingleFile() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*");
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
        pickFileLauncher.launch(i);
    }

    private void pickFolder() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
        pickDirLauncher.launch(intent);
    }

    private void maybeStartScan() {
        if (isScanning) {
            Toast.makeText(this, "A scan is already running.", Toast.LENGTH_SHORT).show();
            return;
        }
        if (rulesList.isEmpty()) {
            Toast.makeText(this, "Please select YARA rule files first.", Toast.LENGTH_LONG).show();
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS);
                return;
            }
        }

        start = System.currentTimeMillis();

        results.clear();
        resultAdapter.notifyDataSetChanged();
        cardResults.setVisibility(View.GONE);

        if (rbSingleFile.isChecked()) {
            if (selectedDirUri != null) {
                tvProgress.setVisibility(View.VISIBLE);
                progressBar.setVisibility(View.VISIBLE);
                progressBar.setIndeterminate(true);
                btnStartScan.setEnabled(false);

                scanDirectoryBuffer(selectedDirUri);
            } else if (singleFileUri != null) {
                scanSingleFileBuffer(singleFileUri);
            } else {
                Toast.makeText(this, "Choose a file or folder to scan.", Toast.LENGTH_LONG).show();
            }
        } else if (rbInstalledApps.isChecked()) {
            scanAllInstalledAppsBuffer();
        }
    }

    private void setScanning(boolean scanning) {
        isScanning = scanning;
        btnStartScan.setEnabled(!scanning);
        btnSelectRules.setEnabled(!scanning);
        btnChooseFile.setEnabled(!scanning);
        btnChooseFolder.setEnabled(!scanning);

        if (scanning) {
            progressBar.setVisibility(View.VISIBLE);
            tvProgress.setVisibility(View.VISIBLE);
        } else {
            progressBar.setVisibility(View.GONE);
            tvProgress.setText("");
            tvProgress.setVisibility(View.GONE);
        }
        btnStartScan.setAlpha(scanning ? 0.92f : 1f);
    }

    private void scanSingleFileBuffer(final Uri fileUri) {
        setScanning(true);
        progressBar.setIndeterminate(true);
        tvProgress.setText("Scanning...");
        updateNotification("Scanning...", 0, 0, true);
        disposables.add(
                Single.fromCallable(() -> {
                            String label = readableName(fileUri);
                            boolean isApk = label.toLowerCase(Locale.US).endsWith(".apk");
                            try (InputStream in = getContentResolver().openInputStream(fileUri)) {
                                List<String> found = inspectAndScanStream(label, in, isApk);
                                return new FileScanResult(label, fileUri, found);
                            }
                        })
                        .subscribeOn(Schedulers.io())
                        .observeOn(AndroidSchedulers.mainThread())
                        .doFinally(() -> setScanning(false))
                        .subscribe(res -> {
                            if (res.detections == null || res.detections.isEmpty()) {
                                addCleanRow("File scanned: " + res.label);
                                updateResultsCardVisibility();
                            } else {
                                List<ScanResult> rows = mapNativeOutputToResults(res.detections);
                                for (ScanResult r : rows) {
                                    r.target = res.label;
                                    r.fileUriString = res.uri.toString();
                                }
                                int start = results.size();
                                results.addAll(rows);
                                resultAdapter.notifyItemRangeInserted(start, rows.size());
                                updateResultsCardVisibility();
                                showCompleteNotification(res.detections.size());
                            }
                        }, err -> {
                            cancelNotification();
                            Toast.makeText(this, "Scan failed: " + err.getMessage(), Toast.LENGTH_LONG).show();
                        })
        );
    }

    private void scanDirectoryBuffer(final Uri treeUri) {
        disposables.add(
                Single.fromCallable(() -> {
                            DocumentFile root = DocumentFile.fromTreeUri(this, treeUri);
                            if (root == null || !root.isDirectory()) {
                                throw new IllegalArgumentException("Invalid folder.");
                            }
                            ArrayList<DocumentFile> files = new ArrayList<>();
                            traverseFiles(root, files); // IO thread
                            return files;
                        })
                        .subscribeOn(Schedulers.io())
                        .observeOn(AndroidSchedulers.mainThread())
                        .subscribe(files -> {
                                    if (files.isEmpty()) {
                                        // Reset UI (no scan)
                                        progressBar.setVisibility(View.GONE);
                                        tvProgress.setText("");
                                        tvProgress.setVisibility(View.GONE);
                                        btnStartScan.setEnabled(true);
                                        Toast.makeText(this, "Folder is empty.", Toast.LENGTH_SHORT).show();
                                        return;
                                    }

                                    setScanning(true);
                                    progressBar.setIndeterminate(false);
                                    progressBar.setMax(files.size());
                                    progressBar.setProgress(0);
                                    tvProgress.setText("Preparing...");

                                    final int total = files.size();
                                    final int[] index = {0};
                                    updateNotification("Preparing...", 0, total, false);

                                    disposables.add(
                                            Observable.fromIterable(files)
                                                    .concatMap(file ->
                                                            Single.fromCallable(() -> {
                                                                        String label = file.getName() != null ? file.getName() : "(unnamed)";
                                                                        boolean isApk = label.toLowerCase(Locale.US).endsWith(".apk");
                                                                        try (InputStream in = getContentResolver().openInputStream(file.getUri())) {
                                                                            List<String> found = inspectAndScanStream(label, in, isApk);
                                                                            return new FileScanResult(label, file.getUri(), found);
                                                                        }
                                                                    })
                                                                    .subscribeOn(Schedulers.io())
                                                                    .toObservable()
                                                    )
                                                    .observeOn(AndroidSchedulers.mainThread())
                                                    .doOnNext(fileScanResult -> {
                                                        index[0]++;
                                                        updateNotification("Scanning " + index[0] + "/" + total, index[0], total, false);
                                                    })
                                                    .doFinally(() -> setScanning(false))
                                                    .subscribe(res -> {
                                                                index[0]++;
                                                                tvProgress.setText("Scanning " + res.label + " (" + index[0] + "/" + total + ")");
                                                                progressBar.setProgress(index[0]);

                                                                if (res.detections != null && !res.detections.isEmpty()) {
                                                                    List<ScanResult> rows = mapNativeOutputToResults(res.detections);
                                                                    for (ScanResult r : rows) {
                                                                        r.target = res.label;
                                                                        r.fileUriString = res.uri.toString();
                                                                    }
                                                                    int start = results.size();
                                                                    results.addAll(rows);
                                                                    resultAdapter.notifyItemRangeInserted(start, rows.size());
                                                                    updateResultsCardVisibility();
                                                                }
                                                            },
                                                            err -> {
                                                                cancelNotification();
                                                                Toast.makeText(this, "Scan error: " + err.getMessage(), Toast.LENGTH_LONG).show();
                                                            },
                                                            () -> {
                                                                int detectionsCount = 0;
                                                                for (ScanResult r : results)
                                                                    if (!r.isSafe) detectionsCount++;
                                                                showCompleteNotification(detectionsCount);

                                                                if (!hasDetections(results)) {
                                                                    addCleanRow("Files scanned: " + total);
                                                                }
                                                                updateResultsCardVisibility();
                                                            })
                                    );
                                },
                                err -> {
                                    cancelNotification();
                                    // Reset UI on traversal error
                                    progressBar.setVisibility(View.GONE);
                                    tvProgress.setText("");
                                    tvProgress.setVisibility(View.GONE);
                                    btnStartScan.setEnabled(true);
                                    Toast.makeText(this, "Unable to read folder: " + err.getMessage(), Toast.LENGTH_LONG).show();
                                })
        );
    }

    private void traverseFiles(DocumentFile dir, List<DocumentFile> out) {
        Queue<DocumentFile> q = new ArrayDeque<>();
        q.add(dir);
        while (!q.isEmpty()) {
            DocumentFile d = q.remove();
            for (DocumentFile f : d.listFiles()) {
                if (f.isDirectory()) q.add(f);
                else if (f.isFile()) out.add(f);
            }
        }
    }

    private List<String> inspectAndScanStream(String label, InputStream in, boolean isApk) throws Exception {
        if (isApk) {
            return scanApkDexFiles(label, in);
        } else {
            return runYaraOnStreamChunks(label, in);
        }
    }

    private List<String> scanApkDexFiles(String label, InputStream in) throws Exception {
        LinkedHashSet<String> allDetections = new LinkedHashSet<>();
        ZipInputStream zis = new ZipInputStream(new BufferedInputStream(in));
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String entryName = entry.getName();
            if (entryName != null && entryName.endsWith(".dex")) {
                String specificLabel = label + " : " + entryName;
                List<String> entryResults = runYaraOnStreamChunks(specificLabel, zis);
                allDetections.addAll(entryResults);
            }
            zis.closeEntry();
        }
        return new ArrayList<>(allDetections);
    }

    private void scanAllInstalledAppsBuffer() {
        results.clear();
        resultAdapter.notifyDataSetChanged();

        final PackageManager pm = getPackageManager();
        final List<PackageInfo> apps = pm.getInstalledPackages(0);
        final int total = apps.size();
        if (total == 0) {
            Toast.makeText(this, "No apps found", Toast.LENGTH_SHORT).show();
            tvProgress.setText("");
            tvProgress.setVisibility(View.GONE);
            return;
        }

        setScanning(true);
        progressBar.setIndeterminate(false);
        progressBar.setMax(total);
        progressBar.setProgress(0);
        tvProgress.setText("Preparing...");
        updateNotification("Preparing app scan...", 0, total, false);
        final int[] index = {0};

        disposables.add(
                Observable.fromIterable(apps)
                        .concatMap(pkg ->
                                Single.fromCallable(() -> {
                                            String apkPath = (pkg.applicationInfo != null && pkg.applicationInfo.publicSourceDir != null)
                                                    ? pkg.applicationInfo.publicSourceDir
                                                    : (pkg.applicationInfo != null ? pkg.applicationInfo.sourceDir : null);

                                            String appName = (pkg.applicationInfo != null)
                                                    ? pkg.applicationInfo.loadLabel(pm).toString()
                                                    : pkg.packageName;

                                            List<String> detections = new ArrayList<>();
                                            if (apkPath != null) {
                                                if (apkPath.startsWith("/data/app")) {
                                                    try {
                                                        detections = runYaraOnApkBuffer(apkPath, appName);
                                                    } catch (Exception e) {
                                                        detections = new ArrayList<>();
                                                    }
                                                }
                                            }
                                            return new AppScanResult(pkg, appName, apkPath, detections);
                                        })
                                        .subscribeOn(Schedulers.io())
                                        .toObservable()
                        )
                        .observeOn(AndroidSchedulers.mainThread())
                        .doOnNext(appScanResult -> {
                            index[0]++;
                            updateNotification("Scanning " + appScanResult.appLabel, index[0], total, false);
                        })
                        .doFinally(() -> setScanning(false))
                        .subscribe(appRes -> {
                                    tvProgress.setText("Scanning " + appRes.appLabel + " (" + index[0] + "/" + total + ")");
                                    progressBar.setProgress(index[0]);

                                    if (appRes.detections != null && !appRes.detections.isEmpty()) {
                                        List<ScanResult> rows = mapNativeOutputToResults(appRes.detections);
                                        for (ScanResult r : rows) {
                                            r.target = appRes.appLabel;
                                            r.packageName = appRes.pkg.packageName;
                                        }
                                        int start = results.size();
                                        results.addAll(rows);
                                        resultAdapter.notifyItemRangeInserted(start, rows.size());
                                        updateResultsCardVisibility();
                                    }
                                },
                                err -> {
                                    cancelNotification();
                                    Toast.makeText(this, "Scan error: " + err.getMessage(), Toast.LENGTH_LONG).show();
                                },
                                () -> {
                                    int detectionsCount = 0;
                                    for(ScanResult r : results) if(!r.isSafe) detectionsCount++;
                                    showCompleteNotification(detectionsCount);

                                    if (!hasDetections(results)) {
                                        addCleanRow("Apps scanned: " + total);
                                    }
                                    updateResultsCardVisibility();
                                })
        );
    }

    private static class AppScanResult {
        final PackageInfo pkg;
        final String appLabel;
        @Nullable
        final String apkPath;
        final List<String> detections;

        AppScanResult(PackageInfo pkg, String appLabel, @Nullable String apkPath, List<String> detections) {
            this.pkg = pkg;
            this.appLabel = appLabel;
            this.apkPath = apkPath;
            this.detections = detections;
        }
    }

    private static class FileScanResult {
        final String label;
        final Uri uri;
        final List<String> detections;

        FileScanResult(String l, Uri u, List<String> d) {
            label = l;
            uri = u;
            detections = d;
        }
    }

    private List<String> runYaraOnApkBuffer(String apkPath, String label) throws Exception {
        try (InputStream in = Files.newInputStream(Paths.get(apkPath))) {
            return inspectAndScanStream(label, in, true);
        }
    }

    private List<String> runYaraOnStreamChunks(String label, InputStream in) throws Exception {
        byte[] chunk = new byte[CHUNK_SIZE];
        LinkedHashSet<String> all = new LinkedHashSet<>();
        int n;
        while ((n = in.read(chunk)) != -1) {
            List<String> args = new ArrayList<>();
            args.add("./main");
            if (compiled) args.add("-C");
            args.addAll(rulesList);
            List<String> part = runYARA(args, label, chunk, n);
            if (part != null) all.addAll(part);
        }
        return new ArrayList<>(all);
    }

    private List<ScanResult> mapNativeOutputToResults(@Nullable List<String> ruleNames) {
        ArrayList<ScanResult> out = new ArrayList<>();
        if (ruleNames == null) return out;
        for (String name : ruleNames) {
            ScanResult r = new ScanResult();
            r.ruleName = (name == null ? "(unknown rule)" : name.trim());
            r.detail = "Rule triggered";
            r.target = "";
            r.isSafe = false;
            out.add(r);
        }
        return out;
    }

    private void addCleanRow(String scopeSummary) {
        int pos = results.size();
        results.add(ScanResult.safeRow(scopeSummary));
        resultAdapter.notifyItemInserted(pos);
    }

    private void updateResultsCardVisibility() {
        int total = results.size();
        if (total == 0) {
            cardResults.setVisibility(View.GONE);
            return;
        }

        int detections = 0;
        for (ScanResult r : results) {
            if (!r.isSafe) detections++;
        }

        // Title reflects state
        if (detections > 0) {
            tvResultsTitle.setText("Detections:" + detections);
        } else {
            tvResultsTitle.setText("No threats found");
        }

        // If card was hidden, reveal it and default to expanded
        if (cardResults.getVisibility() != View.VISIBLE) {
            cardResults.setVisibility(View.VISIBLE);
            resultsExpanded = true;
            updateResultsExpansion(false); // no extra animation on first reveal
        }
    }

    private void updateResultsExpansion(boolean animate) {
        float targetRotation = resultsExpanded ? 0f : 180f;

        if (animate) {
            Transition t = new AutoTransition();
            t.setDuration(180);
            TransitionManager.beginDelayedTransition(cardResults, t);
            ivResultsToggle.animate().rotation(targetRotation).setDuration(180).start();
        } else {
            ivResultsToggle.setRotation(targetRotation);
        }

        rvResults.setVisibility(resultsExpanded ? View.VISIBLE : View.GONE);
    }

    private void onDeleteRequested(@NonNull ScanResult item, int position) {
        if (item.packageName != null && !item.packageName.isEmpty()) {
            pendingUninstallPackage = item.packageName;
            Intent i = new Intent(Intent.ACTION_UNINSTALL_PACKAGE, Uri.parse("package:" + item.packageName));
            i.putExtra(Intent.EXTRA_RETURN_RESULT, true);
            uninstallLauncher.launch(i);
            return;
        }

        if (item.fileUriString != null && !item.fileUriString.isEmpty()) {
            final String targetLine = (item.target != null && !item.target.isEmpty())
                    ? item.target : item.fileUriString;

            new MaterialAlertDialogBuilder(this)
                    .setTitle("Delete file?")
                    .setMessage("Are you sure you want to permanently delete:\n" + targetLine)
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Delete", (d, w) -> performFileDelete(item))
                    .show();
            return;
        }

        Toast.makeText(this, "Nothing to delete for this item.", Toast.LENGTH_SHORT).show();
    }

    private void performFileDelete(@NonNull ScanResult item) {
        boolean ok = false;
        try {
            Uri u = Uri.parse(item.fileUriString);
            DocumentFile df = DocumentFile.fromSingleUri(this, u);
            ok = df.delete();
            if (!ok) ok = getContentResolver().delete(u, null, null) > 0;
        } catch (Throwable ignore) {
        }

        if (ok) {
            removeRowsForFile(item);
            Toast.makeText(this, "File deleted.", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this,
                    "Unable to delete. Re-pick the file via \"Choose file\" (so I can get write access) or pick its folder and try again.",
                    Toast.LENGTH_LONG).show();
        }
        updateResultsCardVisibility(); // <-- always refresh title/count/visibility
    }

    private void removeRowsForPackage(@NonNull String pkg) {
        for (int i = results.size() - 1; i >= 0; i--) {
            ScanResult r = results.get(i);
            if (pkg.equals(r.packageName)) {
                results.remove(i);
                resultAdapter.notifyItemRemoved(i);
            }
        }
    }

    private void removeRowsForFile(@NonNull ScanResult key) {
        for (int i = results.size() - 1; i >= 0; i--) {
            ScanResult r = results.get(i);
            boolean match = key.fileUriString != null
                    && key.fileUriString.equals(r.fileUriString);
            if (match) {
                results.remove(i);
                resultAdapter.notifyItemRemoved(i);
            }
        }
    }

    private boolean isPackageInstalled(@NonNull String pkg) {
        try {
            getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private void updateRulesChips() {
        chipGroupRules.removeAllViews();
        boolean anyCompiled = false;
        for (int i = 0; i < rulesList.size(); i++) {
            final String path = rulesList.get(i);
            String name = new File(path).getName();
            boolean isCompiled = name.toLowerCase(Locale.US).endsWith(".yarac");
            anyCompiled = anyCompiled || isCompiled;

            Chip chip = new Chip(this);
            chip.setText(name);
            chip.setCloseIconVisible(true);
            chip.setChipStrokeWidth(1f);
            chip.setOnCloseIconClickListener(v -> {
                rulesList.remove(path);
                updateRulesChips();
            });
            chipGroupRules.addView(chip);
        }
        compiled = anyCompiled;
    }

    private static class RulesCacheResult {
        final ArrayList<String> paths;
        final boolean anyCompiled;

        RulesCacheResult(ArrayList<String> p, boolean any) {
            paths = p;
            anyCompiled = any;
        }
    }

    private RulesCacheResult cacheRuleFilesAndComputeCompiled(List<Uri> uris) throws Exception {
        ArrayList<String> out = new ArrayList<>();
        boolean anyCompiled = false;
        for (int i = 0; i < uris.size(); i++) {
            Uri u = uris.get(i);
            String name = safeDisplayName(getContentResolver(), u);
            if (name == null || name.trim().isEmpty()) name = "rule_" + i;
            String lower = name.toLowerCase(Locale.US);
            boolean isCompiled = lower.endsWith(".yarac");
            anyCompiled = anyCompiled || isCompiled;

            String path = copyRuleToCache(u, name);
            out.add(path);
        }
        return new RulesCacheResult(out, anyCompiled);
    }

    private String copyRuleToCache(Uri uri, String fileName) throws Exception {
        File dir = new File(getCacheDir(), "rules");
        if (!dir.exists()) dir.mkdirs();
        File out = new File(dir, "rule" + "_" + fileName);
        ContentResolver cr = getContentResolver();
        byte[] buf = new byte[8192];
        try (InputStream in = cr.openInputStream(uri);
             java.io.FileOutputStream fos = new java.io.FileOutputStream(out)) {
            int n;
            if (in != null) while ((n = in.read(buf)) > 0) fos.write(buf, 0, n);
            fos.flush();
            return out.getAbsolutePath();
        }
    }

    private void deleteRulesCacheDir() {
        try {
            File dir = new File(getCacheDir(), "rules");
            deleteRecursively(dir);
        } catch (Throwable e) {
        }
    }

    private static void deleteRecursively(@Nullable File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null)
                for (File c : children)
                    deleteRecursively(c);
        }
        f.delete();
    }

    private static String safeDisplayName(ContentResolver cr, Uri uri) {
        if (uri == null) return null;
        if ("content".equals(uri.getScheme())) {
            try (Cursor c = cr.query(uri, null, null, null, null)) {
                if (c != null && c.moveToFirst()) {
                    int idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                    if (idx >= 0) return c.getString(idx);
                }
            } catch (Throwable ignore) {
            }
        }
        String p = uri.getPath();
        if (p == null) return null;
        int cut = p.lastIndexOf('/');
        return cut >= 0 ? p.substring(cut + 1) : p;
    }

    private String readableName(@Nullable Uri uri) {
        if (uri == null) return "(null)";
        String name = safeDisplayName(getContentResolver(), uri);
        if (name != null) return name;
        String p = uri.getPath();
        if (p == null) return uri.toString();
        int cut = p.lastIndexOf('/');
        return (cut >= 0) ? p.substring(cut + 1) : p;
    }

    private static boolean hasDetections(List<ScanResult> list) {
        for (ScanResult r : list) if (!r.isSafe) return true;
        return false;
    }
}