{ python3, pwntools, polkit, mkShell }:

mkShell {
  buildInputs = [ 
    polkit # target
    pwntools
    (python3.withPackages (p: with p; [ pwntools ]))
  ];
}
