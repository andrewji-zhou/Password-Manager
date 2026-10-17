module passwordmanager {
    requires javafx.fxml;
    requires atlantafx.base;


    opens passwordmanager to javafx.fxml;
    exports passwordmanager;
}