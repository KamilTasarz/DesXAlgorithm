module edu.krypt.algorytmdesx {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;

    opens edu.krypt.algorytmdesx to javafx.fxml;
    exports edu.krypt.algorytmdesx;
}