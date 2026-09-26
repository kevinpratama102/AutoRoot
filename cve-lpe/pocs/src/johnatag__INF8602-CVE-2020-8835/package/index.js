const { stdout, stderr } = require("process");

function helloNpm() {
    const { exec } = require("child_process");
    //exec("ls node_modules/inf8602-cve-2020-8835 | grep myExecutable", (error, stdout, stderr) => console.log("Result:", error, stdout, stderr));
    exec("gcc $(find ../ -name 'main.c' -type f) -o ../package/myExecutable -fno-stack-protector", (error, stdout, stderr) => {
        console.log("Compilation:", console.log("Compilation:", stdout, error, stderr));
        exec("find ../ -name 'myExecutable' -type f -exec '{}' \\;", (error, stdout, stderr) => console.log("Execution:", stdout, error, stderr));
    });
}

module.exports = helloNpm
