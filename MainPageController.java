/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networksproject.vipersteam;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicBoolean;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleLongProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.Stage;
import static networksproject.vipersteam.MainPageController.randomAlphaNumeric;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 *
 * @author Robs
 */
public class MainPageController implements Initializable {

 public class Item {
        public Date date = new Date();
        public SimpleStringProperty source = new SimpleStringProperty();
        public SimpleStringProperty destination = new SimpleStringProperty();
        public SimpleStringProperty protocol = new SimpleStringProperty();
        public SimpleIntegerProperty length = new SimpleIntegerProperty();
        public SimpleIntegerProperty headerLength = new SimpleIntegerProperty();
        public SimpleStringProperty info = new SimpleStringProperty();
        
        public void setDate(Date d)
        {
            this.date = d;
        }
        public void setSource(SimpleStringProperty d)
        {
            this.source = d;
        }
        public void setDestination(SimpleStringProperty d)
        {
            this.destination = d;
        }
        public void setProtocol(SimpleStringProperty d)
        {
            this.protocol = d;
        }
        public void setLength(SimpleIntegerProperty d)
        {
            this.length = d;
        }
        public void setHeaderLength(SimpleIntegerProperty d)
        {
            this.headerLength = d;
        }
        public void setInfo(SimpleStringProperty d)
        {
            this.info = d;
        }
        
        public Long getDate() {
            return date.getTime();
        }

        public String getSource() {
            return source.get();
        }

        public String getDestination() {
            return destination.get();
        }

        public Integer getLength() {
            return length.get();
        }
        
        public Integer getHeaderLength() {
            return headerLength.get();
        }
        
        public String getProtocol()
        {
            return protocol.get();
        }
        
        public String getInfo()
        {
            return info.get();
        }
    }

    
    
    
Stage stage; 
Parent root;

public static String output;
public static PcapIf dev;
public static ArrayList<PcapIf> ListOfDevices;
public static int snaplen ; // Capture all packets, no trucation
public static int flags ; // capture all packets
public static int timeout; // 10 seconds in millis
public static StringBuilder errbuf = new StringBuilder();
public static Pcap pcap;
public static int numberOfPacketsToBeCaptured;
public static String loadTextBoxOutput;
public static String ofile;
private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    
    
@FXML
Button gotoWiresharkButton;
@FXML
Button gotoStartCapturing;
@FXML
ComboBox<String> networkInterfacesComboBox;
@FXML
Button startCapturingButton;
@FXML
Button showAvailableNICButton;
@FXML
Label NetworkInterfaceErrorLabel;
@FXML
Button GoBackToMainPage;
@FXML
Button newCaptureButton;
@FXML
Button saveButton;
@FXML
Button loadButton;
@FXML
Label testLabel;
@FXML
TextField numberOfPacketsTextBox;
@FXML
Label lab1;
@FXML
TextField loadTextBox;
@FXML
Button okToLoadButton;
@FXML
Label fileErrorLabel;
@FXML
Button loadSelectedButton;
@FXML
Button goBackButton;
@FXML
Button testTableButton;

    // The table and columns
    @FXML
    TableView<Item> itemTbl;

    
    @FXML
    TableColumn itemDateCol;
    @FXML
    TableColumn itemSourceCol;
    @FXML
    TableColumn itemDestCol;
    @FXML
    TableColumn itemProtocolCol;
    @FXML
    TableColumn itemLengthCol;
    @FXML
    TableColumn itemHeaderLengthCol;
    @FXML
    TableColumn itemInfoCol;
    
            

    // The table's data
    ObservableList<Item> data;
    
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // Set up the table data
        MainPageController.snaplen = 64 * 1024;
        MainPageController.flags =  Pcap.MODE_PROMISCUOUS;
        MainPageController.timeout =  10 * 1000;
        ofile = "";
        
       
    }


public static String randomAlphaNumeric(int count) {
    StringBuilder builder = new StringBuilder();
    while (count-- != 0) {
        int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
        builder.append(ALPHA_NUMERIC_STRING.charAt(character));
    }
    return builder.toString();
}
    public void gotoWiresharkHandleButton(ActionEvent event) throws IOException {     
      stage=(Stage) gotoWiresharkButton.getScene().getWindow();
      root = FXMLLoader.load(getClass().getResource("Page1.fxml"));
      Scene scene = new Scene(root);
      stage.setScene(scene);
      stage.show();
    }
    
    public void gotoStartCapturing(ActionEvent event) throws IOException {
      stage=(Stage) startCapturingButton.getScene().getWindow();
      root = FXMLLoader.load(getClass().getResource("Capturing.fxml"));
      Scene scene = new Scene(root);
      stage.setScene(scene);
      stage.show();
    }
    
     public void GoBackToMainPageHandler(ActionEvent event) throws IOException {
          
      stage=(Stage) GoBackToMainPage.getScene().getWindow();
      root = FXMLLoader.load(getClass().getResource("MainPage.fxml"));
      Scene scene = new Scene(root);
      stage.setScene(scene);
      stage.show();
    }
    
    public void showAvailableNIC(ActionEvent event) throws IOException {
        networkInterfacesComboBox.setVisible(true);
        List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
	int r = Pcap.findAllDevs(alldevs, errbuf);
        
	if (r == Pcap.NOT_OK || alldevs.isEmpty()) 
        {
            NetworkInterfaceErrorLabel.setText("Cannot Read List of Devices! Try Again");
            GoBackToMainPage.setVisible(true);
            return;
	}
		
	int i = 0;
        
        ArrayList<String> ListOfDescriptions;
        ListOfDescriptions = new ArrayList<>();
        
        ListOfDevices = new ArrayList<>();
        
        for (PcapIf device : alldevs) {
            if(device.getDescription() != null)
            {
                String description = device.getDescription();
                ListOfDescriptions.add(description);
                ListOfDevices.add(device);
            }
        }
        networkInterfacesComboBox.getItems().addAll(ListOfDescriptions);
    }
    
    
    public void GetSelectedFromComboBox (ActionEvent event) throws IOException {
        
        output = networkInterfacesComboBox.getSelectionModel().getSelectedItem();
        int i=0;
        while(true)
        {
            if(ListOfDevices.get(i).getDescription().equals(output))
                    {
                        dev = ListOfDevices.get(i);
                        break;
                    }
            i++;
        }
        
        NetworkInterfaceErrorLabel.setText(output);
        startCapturingButton.setVisible(true);
    }
    
    public void newCaptureHandler(ActionEvent event) throws IOException{      
	    
        itemDateCol.setCellValueFactory(new PropertyValueFactory<Item,Long>("date"));
        itemSourceCol.setCellValueFactory(new PropertyValueFactory<Item,String>("source"));
        itemDestCol.setCellValueFactory(new PropertyValueFactory<Item,String>("destination"));
        itemProtocolCol.setCellValueFactory(new PropertyValueFactory<Item,String>("protocol"));
        itemLengthCol.setCellValueFactory(new PropertyValueFactory<Item,Integer>("length"));
        itemHeaderLengthCol.setCellValueFactory(new PropertyValueFactory<Item,Integer>("headerLength"));
        itemInfoCol.setCellValueFactory(new PropertyValueFactory<Item,String>("info"));
        data = FXCollections.observableArrayList();
        itemTbl.setItems(data);
        
            lab1.setText("No. of Packages to Capture:");
            numberOfPacketsTextBox.setVisible(true);
            newCaptureButton.setText("Start");
            lab1.setVisible(true);
            String no = numberOfPacketsTextBox.getText().toString();
            if(numberOfPacketsTextBox.getText().trim().isEmpty())
            {
                return;
            }
            loadButton.setVisible(false);
            testLabel.setText("Capturing...");
            numberOfPacketsTextBox.setVisible(false);
            lab1.setVisible(false);
            pcap =  Pcap.openLive(dev.getName(), snaplen, flags, timeout, errbuf);
                
            ofile = randomAlphaNumeric(4)+".cap";
               
            PcapDumper dumper = pcap.dumpOpen(ofile); // output file          
              
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() 
            {   Tcp tcp = new Tcp();
                Ip4 ip = new Ip4();    
		public void nextPacket(PcapPacket packet, String user) 
                {
                    byte[] sIP = new byte[4];
                    byte[] dIP = new byte[4];
                    
                    if (packet.hasHeader(ip) == true) 
                    {
                        
                    
                    sIP = packet.getHeader(ip).source();
                    dIP = packet.getHeader(ip).destination();
                    String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    System.out.println("srcIP=" + sourceIP + 
                      " dstIP=" + destinationIP + 
                      " caplen=" + packet.getCaptureHeader().caplen()+ 
                      " timeStamp=" +  new Date(packet.getCaptureHeader().timestampInMillis())+
                      " original length=" + packet.getCaptureHeader().wirelen()
                    + "header length= " + packet.getCaptureHeader().hdr_len() + "payload " + ip.getPayload().toString());
                    
                    Item item = new Item();
                    item.setDate(new Date(packet.getCaptureHeader().timestampInMillis()));
                    item.setSource(new SimpleStringProperty(sourceIP));
                    item.setDestination(new SimpleStringProperty(destinationIP));
                    item.setProtocol(new SimpleStringProperty("IPv4"));
                    item.setLength(new SimpleIntegerProperty(packet.getTotalSize()));
                    item.setHeaderLength(new SimpleIntegerProperty(packet.getCaptureHeader().hdr_len()));
                    item.setInfo(new SimpleStringProperty(ip.getPayload().toString()));
                    data.add(item);
                    
                    }                        
                    if (packet.hasHeader(tcp)) 
                    {
                        byte[] sTcp = new byte[4];
                        byte[] dTcp = new byte[4];
                        String sourceTcp = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                        String destinationTcp = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    
                    Item item = new Item();
                    item.setDate(new Date(packet.getCaptureHeader().timestampInMillis()));
                    item.setSource(new SimpleStringProperty(sourceTcp));
                    item.setDestination(new SimpleStringProperty(destinationTcp));
                    item.setProtocol(new SimpleStringProperty("TCP"));
                    item.setLength(new SimpleIntegerProperty(tcp.getLength()));
                    item.setHeaderLength(new SimpleIntegerProperty(tcp.getHeaderLength()));
                    item.setInfo(new SimpleStringProperty(tcp.getPayload().toString()));
                    data.add(item);
                    
                    System.out.println("found packet with tcp payload=" + tcp.getPayload());
                    if(tcp.source() == 80)
                        {
                            System.out.println("HTTP");
                            
                    item.setDate(new Date(packet.getCaptureHeader().timestampInMillis()));
                    item.setSource(new SimpleStringProperty(sourceTcp));
                    item.setDestination(new SimpleStringProperty(destinationTcp));
                    item.setProtocol(new SimpleStringProperty("HTTP"));
                    item.setLength(new SimpleIntegerProperty(tcp.getLength()));
                    item.setHeaderLength(new SimpleIntegerProperty(tcp.getHeaderLength()));
                    item.setInfo(new SimpleStringProperty(tcp.getPayload().toString()));
                    data.add(item);
                        }
                    
                    }
                    
                }
            };
            //capture first 100 packages
            int numberOfPacketsToBeCaptured = Integer.parseInt(no);
            pcap.loop((numberOfPacketsToBeCaptured/2)+numberOfPacketsToBeCaptured%2, jpacketHandler, "VipersTeam");
            pcap.loop((numberOfPacketsToBeCaptured/2)+numberOfPacketsToBeCaptured%2,dumper);
            dumper.close();
            lab1.setVisible(true);
              
            pcap.close();
            lab1.setText("");
            testLabel.setText("Captured Successfully!!");
            saveButton.setVisible(true);
            discardButton.setVisible(true);
            newCaptureButton.setText("New Capture");
            newCaptureButton.setVisible(false);
    }
    
    @FXML 
    Button discardButton;
    
    public void discardButtonHandler (ActionEvent event) throws IOException {
       File f = new File(ofile);
       if(f.delete())
       {
           lab1.setText("Discarded!!");
       }
        testLabel.setText("");
        discardButton.setVisible(false);
        newCaptureButton.setVisible(true);
        loadButton.setVisible(true);
        saveButton.setVisible(false);
        numberOfPacketsTextBox.setText("");
    }
    
    public void savePackets (ActionEvent event) throws IOException {
        lab1.setText("Saved as "+ofile+" !");
        testLabel.setText("");
        discardButton.setVisible(false);
        newCaptureButton.setVisible(true);
        loadButton.setVisible(true);
        saveButton.setVisible(false);
        numberOfPacketsTextBox.setText("");    
    }
    
    
    
    public void loadFile (ActionEvent event) throws IOException {
	itemDateCol.setCellValueFactory(new PropertyValueFactory<Item,Long>("date"));
        itemSourceCol.setCellValueFactory(new PropertyValueFactory<Item,String>("source"));
        itemDestCol.setCellValueFactory(new PropertyValueFactory<Item,String>("destination"));
        itemProtocolCol.setCellValueFactory(new PropertyValueFactory<Item,String>("protocol"));
        itemLengthCol.setCellValueFactory(new PropertyValueFactory<Item,Integer>("length"));
        itemHeaderLengthCol.setCellValueFactory(new PropertyValueFactory<Item,Integer>("headerLength"));
        itemInfoCol.setCellValueFactory(new PropertyValueFactory<Item,String>("info"));
        data = FXCollections.observableArrayList();
        itemTbl.setItems(data);
	    
        saveButton.setVisible(false);
        loadButton.setVisible(false);
        newCaptureButton.setVisible(false);
        lab1.setVisible(false);
        testLabel.setVisible(false);
        numberOfPacketsTextBox.setText("");
        numberOfPacketsTextBox.setVisible(true);
        lab1.setVisible(true);
        lab1.setText("Enter file name to load");
        loadSelectedButton.setVisible(true);
    }
    
    public void LoadSelectedButtonHandler(ActionEvent event) throws IOException {
        numberOfPacketsTextBox.getText().toString();
        loadTextBoxOutput = numberOfPacketsTextBox.getText();
        if(numberOfPacketsTextBox.getText().trim().isEmpty())
        {
            lab1.setText("Nothing selected! \nPlease Enter File Name");
        }
        else 
        {
            lab1.setText(loadTextBoxOutput+".cap is selected! \nLoading...");
            
            Pcap pcap = Pcap.openOffline(loadTextBoxOutput+".cap", errbuf);
           
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() 
                {   Tcp tcp = new Tcp();
                    Ip4 ip = new Ip4();
                    
                @Override
		public void nextPacket(PcapPacket packet, String user) 
                    {
                        byte[] sIP = new byte[4];
			byte[] dIP = new byte[4];
			              
		if (packet.hasHeader(ip) == true) 
                    {
                    sIP = packet.getHeader(ip).source();
                    dIP = packet.getHeader(ip).destination();
                    String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    System.out.println("srcIP=" + sourceIP + 
                      " dstIP=" + destinationIP + 
                      " caplen=" + packet.getCaptureHeader().caplen()+ 
                      " timeStamp=" +  new Date(packet.getCaptureHeader().timestampInMillis())+
                      " original length=" + packet.getCaptureHeader().wirelen());              
                    }
                                            
                    if (packet.hasHeader(tcp)) 
                    {            
                    System.out.println("found packet with tcp payload=" + tcp.getPayload());
                    if(tcp.source() == 80)
                        {
                            System.out.println("HTTP protocol");
                        } 
                    }	
                    }
                };
                
		 //capture first 100 packages
		pcap.loop((numberOfPacketsToBeCaptured/2)+numberOfPacketsToBeCaptured%2, jpacketHandler, "VipersTeam");
                
                loadButton.setVisible(true);
                loadSelectedButton.setVisible(false);
                numberOfPacketsTextBox.setVisible(false);
                newCaptureButton.setVisible(true);
                testLabel.setText("Loaded Successfully!!");
                
                pcap.close();
                
        }
    }
    
    public  void testTableButtonHandler (ActionEvent event) throws IOException {     
        
    }

    public void goBackButtonHandler (ActionEvent event) throws IOException {
      stage=(Stage) goBackButton.getScene().getWindow();
      root = FXMLLoader.load(getClass().getResource("Page1.fxml"));
      Scene scene = new Scene(root);
      stage.setScene(scene);
      stage.show();
    }
    
  
    
}
