<?php
if (isset($argc)){
    if ($argc ==1){
        echo "no arguments have been passed\n";
    }
    else if($argc > 2){
        echo "Too many arguments, only one (PW) required";
    }
    else {
        $options = [
            'cost' => 16,
        ];
        echo "{BCRYPT}".password_hash($argv[1],PASSWORD_BCRYPT,$options);

    }
}
else {
    echo "argc/argv disabled\n";
}
//echo(password_verify('tesD2jdDasjdA12OI2','$2b$16$eJHXXt39....n51b6l6...fabyI1g0oeasNflQ3QspUaLbmmtp3Tm'))
?>