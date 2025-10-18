package com.android.yara.adapter;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.android.yara.R;
import com.android.yara.model.ScanResult;
import com.google.android.material.button.MaterialButton;

import java.util.List;

public class ScanResultAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    public interface OnActionListener {
        void onDelete(@NonNull ScanResult item, int position);
    }

    private static final int TYPE_DETECTION = 0;
    private static final int TYPE_SAFE = 1;

    private final List<ScanResult> items;
    private OnActionListener listener;

    public ScanResultAdapter(@NonNull List<ScanResult> items) {
        this.items = items;
    }

    public void setOnActionListener(OnActionListener l) {
        this.listener = l;
    }

    @Override
    public int getItemViewType(int position) {
        ScanResult r = items.get(position);
        return (r != null && r.isSafe) ? TYPE_SAFE : TYPE_DETECTION;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inf = LayoutInflater.from(parent.getContext());
        if (viewType == TYPE_SAFE) {
            View v = inf.inflate(R.layout.item_scan_result_safe, parent, false);
            return new SafeVH(v);
        } else {
            View v = inf.inflate(R.layout.item_scan_result, parent, false);
            return new DetectionVH(v);
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder h, int position) {
        ScanResult r = items.get(position);
        if (getItemViewType(position) == TYPE_SAFE) {
            SafeVH s = (SafeVH) h;
            s.tvTitle.setText(!TextUtils.isEmpty(r.ruleName) ? r.ruleName : "Clean — no threats found");
            s.tvSubtitle.setText(r.detail != null ? r.detail : "");
        } else {
            DetectionVH d = (DetectionVH) h;
            d.tvRuleName.setText(r.ruleName != null ? r.ruleName : "(unknown rule)");
            d.tvTarget.setText(buildFileOnlyTargetText(d.itemView.getContext(), r));
            d.btnDelete.setOnClickListener(v -> {
                if (listener != null) listener.onDelete(r, d.getBindingAdapterPosition());
            });
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    public void removeAt(int position) {
        items.remove(position);
        notifyItemRemoved(position);
    }

    private static String buildFileOnlyTargetText(Context ctx, @NonNull ScanResult r) {
        if (!TextUtils.isEmpty(r.packageName)) {
            return "Target: " + r.packageName; // apps: no file path
        }
        if (!TextUtils.isEmpty(r.filePath)) {
            return "Target: " + r.filePath;
        }
        if (!TextUtils.isEmpty(r.fileUriString)) {
            return "Target: " + prettyPathFromUri(ctx, r.fileUriString);
        }
        if (!TextUtils.isEmpty(r.target)) {
            return "Target: " + r.target;
        }
        return "Target: —";
    }

    private static String prettyPathFromUri(Context ctx, @NonNull String uriStr) {
        try {
            Uri uri = Uri.parse(uriStr);
            String scheme = uri.getScheme();
            if ("file".equalsIgnoreCase(scheme)) {
                return uri.getPath() != null ? uri.getPath() : Uri.decode(uri.toString());
            }
            if ("content".equalsIgnoreCase(scheme)) {
                if (DocumentsContract.isDocumentUri(ctx, uri)) {
                    final String docId = safeGetDocumentId(uri);
                    if (isExternalStorageDocument(uri)) {
                        if (docId != null) {
                            if (docId.startsWith("raw:")) return docId.substring(4);
                            String[] split = docId.split(":");
                            if (split.length >= 2) {
                                String vol = split[0];
                                String rel = split[1];
                                if ("primary".equalsIgnoreCase(vol))
                                    return "/storage/emulated/0/" + rel;
                                return "/storage/" + vol + "/" + rel;
                            }
                        }
                    } else if (isDownloadsDocument(uri)) {
                        String name = queryDisplayName(ctx, uri);
                        if (!TextUtils.isEmpty(name)) return "/Download/" + name;
                    } else if (isMediaDocument(uri)) {
                        String name = queryDisplayName(ctx, uri);
                        String base = baseForMediaType(docId);
                        if (!TextUtils.isEmpty(name)) return base + name;
                    }
                }
                String name = queryDisplayName(ctx, uri);
                if (!TextUtils.isEmpty(name)) return name;
                return Uri.decode(uri.toString());
            }
            return Uri.decode(uri.toString());
        } catch (Throwable t) {
            return uriStr;
        }
    }

    private static String safeGetDocumentId(@NonNull Uri uri) {
        try {
            return DocumentsContract.getDocumentId(uri);
        } catch (Throwable ignore) {
            return null;
        }
    }

    private static boolean isExternalStorageDocument(Uri uri) {
        return "com.android.externalstorage.documents".equals(uri.getAuthority());
    }

    private static boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }

    private static boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    private static String baseForMediaType(String docId) {
        if (docId == null) return "/Media/";
        String type = docId.contains(":") ? docId.substring(0, docId.indexOf(':')) : docId;
        switch (type) {
            case "image":
                return "/Pictures/";
            case "video":
                return "/Movies/";
            case "audio":
                return "/Music/";
            default:
                return "/Media/";
        }
    }

    private static String queryDisplayName(Context ctx, Uri uri) {
        ContentResolver cr = ctx.getContentResolver();
        try (Cursor c = cr.query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) return c.getString(idx);
            }
        } catch (Throwable ignore) {
        }
        return null;
    }

    static class DetectionVH extends RecyclerView.ViewHolder {
        final TextView tvRuleName, tvTarget;
        final MaterialButton btnDelete;

        DetectionVH(@NonNull View itemView) {
            super(itemView);
            tvRuleName = itemView.findViewById(R.id.tvRuleName);
            tvTarget = itemView.findViewById(R.id.tvTarget);
            btnDelete = itemView.findViewById(R.id.btnDelete);
        }
    }

    static class SafeVH extends RecyclerView.ViewHolder {
        final ImageView ivSafeIcon;
        final TextView tvTitle, tvSubtitle;

        SafeVH(@NonNull View itemView) {
            super(itemView);
            ivSafeIcon = itemView.findViewById(R.id.ivSafeIcon);
            tvTitle = itemView.findViewById(R.id.tvSafeTitle);
            tvSubtitle = itemView.findViewById(R.id.tvSafeSubtitle);
        }
    }
}