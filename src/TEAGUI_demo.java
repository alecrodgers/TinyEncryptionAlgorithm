//package v5;

import javafx.scene.control.*;
import javafx.scene.shape.*;
import javafx.application.*;
import javafx.geometry.Insets;
import javafx.stage.Stage;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.Scene;
import java.io.*;
import java.util.*;

public class TEAGUI_demo extends Application {

	// GUI variables
	BorderPane root = new BorderPane();
	HBox hBox = new HBox();
	GridPane top = new GridPane();
	Pane graph = new Pane();

	@Override
	public void start(Stage primaryStage) throws Exception {

		root.setCenter(hBox);
		root.setBottom(graph);

		// Padding
		root.setPadding(new Insets(15));

		// TEAENGINE GUI TEST
		// Set whether Cipher Block Chaining is used during encryption;
		
		boolean isCBC = false;

		// Array for Key Values
		int[] keys = new int[] { 0x1310914, 0x1310916, 0x13107FD, 0x1301D30 };

		// Initialization Vector
		int iv[] = new int[] { 0xE8E804, 0x2b21a3aa };

		// ArrayList for inputLongs

		// ArrayList For inputStream represented as HexValues
		ArrayList<Integer> inputValues = new ArrayList<>();

		// First Block
		inputValues.add(0xffffeb);
		inputValues.add(0x212DEEE);

		// Second Block
		inputValues.add(0xbbbee1);
		inputValues.add(0x3A152ac6);

		// Third Block
		inputValues.add(0x1200014);
		inputValues.add(0xe300012);

		// Fourth Block
		inputValues.add(0x2bbac11);
		inputValues.add(0xa12512c9);

		// new TEAEngine Object
		TEAEngineV5 eEngine = new TEAEngineV5(inputValues, keys, iv, isCBC);
		eEngine.encrypt();
		eEngine.decrypt();

		// add points to list of int[]
		eEngine.addPoints(eEngine.getEncPointList(), eEngine.getEncryptedCharArr());
		eEngine.addPoints(eEngine.getDecpointList(), eEngine.getDecryptedCharArr());
		
		
		
		
		
		// setting int[] instances to the complete point arrays
		int[] allEncPoints = eEngine.getFullEncPointsArr();
		int[] allDecPoints = eEngine.getFullDecPointsArr();

		hBox.setSpacing(25);

		// hBox.getChildren().add(new Label(eEngine.printInputBlocks()));
		hBox.getChildren().add(new Label("Config:\n\n" + "CBC mode:"+eEngine.isCBC() + "\n" + "Encoder Generation: Random"));
		hBox.getChildren().add(new Label("Original Input:\n\n" + eEngine.printInputBlocks()));
		hBox.getChildren().add(new Label("Encrypted Output:\n\n" + eEngine.printEncryptedOutput()));
		hBox.getChildren().add(new Label("Decrypted Output:\n\n" + eEngine.printDecryptedOutput()));
		

		// container for storing circle objects
		ArrayList<Circle> graphCircles1 = new ArrayList<>();
		ArrayList<Circle> graphCircles2 = new ArrayList<>();
		ArrayList<Circle> grpahCircles3 = new ArrayList<>();

		for (int i = 0; i < allEncPoints.length; i++) {
			graphCircles1.add(new Circle(i * 2.2 + 50, (allEncPoints[i] * 0.7) + 100, 1));
		}

		for (int i = 0; i < allDecPoints.length; i++) {
			graphCircles2.add(new Circle(i * 2.2 + 650, (allDecPoints[i] * 0.7) + 100, 1));
		}

		

		for (Circle c : graphCircles1) {
			// graph.getChildren().add(c);
		}

		// draw lines in graph1
		for (int i = 0; i < graphCircles1.size() - 1; i++) {

			Circle c1 = graphCircles1.get(i);
			Circle c2 = graphCircles1.get(i + 1);

			Line line = new Line(c1.getCenterX(), c1.getCenterY(), c2.getCenterX(), c2.getCenterY());
			line.setStrokeWidth(.5);

			graph.getChildren().add(line);

		}

		// draw lines in graph2
		for (int i = 0; i < graphCircles2.size() - 1; i++) {

			Circle c1 = graphCircles2.get(i);
			Circle c2 = graphCircles2.get(i + 1);

			Line line = new Line(c1.getCenterX(), c1.getCenterY(), c2.getCenterX(), c2.getCenterY());
			line.setStrokeWidth(.5);
			line.setStroke(Color.RED);
			graph.getChildren().add(line);

		}
		
		

		// // draw some circles
		// for (int i = 0; i < 620; i++) {
		// graph.getChildren().add(new Circle(i * 2, 50 + (Math.random() * 40), 2));
		// }

		Scene scene = new Scene(root, 1400, 800);
		primaryStage.setTitle("TEA Test Display");
		primaryStage.setScene(scene);
		primaryStage.sizeToScene();
		primaryStage.show();
	}

	public static void main(String[] args) {
		launch(args);
	}

}
