<?php
$servername = "lnmp_mysql"; // docker "links" populate this in /etc/hosts
$username = "petstore";
$password = "redhat12345";
$database = "petstore";
$port = 3306;

// Create connection
$conn = new mysqli($servername, $username, $password, $database, $port);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
//echo "Connected successfully";

$sql = "SELECT name from pets";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    // output data of each row
    while($row = $result->fetch_assoc()) {
        echo "Name: " . $row["name"];
    }
} else {
    echo "0 results";
}
?>
