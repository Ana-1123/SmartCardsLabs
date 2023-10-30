/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package health;

import javacard.framework.*;
import javacardx.annotations.*;
import static health.HealthStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "health"),
	    @StringDef(name = "AppletName", value = "Health")},
	    // Insert your strings here 
	name = "HealthStrings")



public class Health extends Applet {
	
	
	/* constants declaration */
	
	// code of CLA byte in the command APDU header
    final static byte Health_CLA = (byte) 0x80;
    final static byte VERIFY = (byte) 0x20;
    final static byte UPDATE = (byte) 0x24;
    final static byte SET_DATA = (byte) 0x30;
    final static byte SET_VACATION = (byte) 0x40;
    final static byte GET_DATA = (byte) 0x50;
    final static byte SET_CONSULT = (byte) 0x70;
   
    
 // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;
    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    final static short SW_INVALID_DATA =0x6A80;
    final static short SW_CONSULT_DENIED = 0x6A83;
    final static short SW_VACATION_DENIED = 0x6A84;
    
	OwnerPIN pin;
	byte[] data_nasterii = {0x0C,0x08,0x00};
	byte grupa_sangv=0x01, rh=0x00, cod_diag_cronic=0x00, cod_spec_cronic=0x00, cod_donator=0x00;
	byte[] start_vacation ={0x00,0x00,0x00}, end_vacation={0x00,0x00,0x00};
	byte[] consult1= {0x00,0x00,0x00,0x00,0x00};
	byte[] consult2= {0x00,0x00,0x00,0x00,0x00};
	byte[] consult3= {0x00,0x00,0x00,0x00,0x00};
	
	
	private Health(byte[] bArray, short bOffset, byte bLength) {

        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        register();

    } // end of the constructor

    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
    	 //create a Health applet instance
         new Health(bArray, bOffset, bLength);
    } // end of install method
    
    
    @Override
    public boolean select() {
        // The applet declines to be selected if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }
        return true;
    }// end of select method
    
    
    @Override
    public void deselect() {
        // reset the pin value
        pin.reset();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
        //Insert your code here
    	
    	byte[] buffer = apdu.getBuffer();    
    	
    	 if (apdu.isISOInterindustryCLA()) {
             if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                 return;
             }
             ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
         }

        if (buffer[ISO7816.OFFSET_CLA] != Health_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
        case VERIFY:
            verify(apdu);
            return;       
        case UPDATE:
            update(apdu);
            return;
        case SET_VACATION:
            set_vacation(apdu);
            return;
        case GET_DATA:
            get_data(apdu);
            return;
        case SET_DATA:
            set_data(apdu);
            return;
        case SET_CONSULT:
            set_consult(apdu);
            return;    
    
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    } // end of process method
        
    
private void verify(APDU apdu) {

    byte[] buffer = apdu.getBuffer();
    // retrieve the PIN data for validation.
    byte byteRead = (byte) (apdu.setIncomingAndReceive());

    // check pin
    // the PIN data is read into the APDU buffer
    // at the offset ISO7816.OFFSET_CDATA
    // the PIN data length = byteRead
    if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
        ISOException.throwIt(SW_VERIFICATION_FAILED);
    }
    } // end of validate method

private void update(APDU apdu) {
	byte[] buffer = apdu.getBuffer();

    // Verify that the user is authenticated
    byte byteRead = (byte) (apdu.setIncomingAndReceive());
    
    if (!pin.isValidated()) {
        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    }
    // Verify that the data field contains ten bytes (5 for current PIN, 5 for new PIN)
    if (buffer[ISO7816.OFFSET_LC] != 10 || byteRead != 10) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // Get the old and new PIN values from the data field
    byte[] oldPIN = new byte[5];
    byte[] newPIN = new byte[5];
    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, oldPIN, (short) 0, (short) 5);
    Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA + 5), newPIN, (short) 0, (short) 5);

    // Verify that the old PIN matches the current PIN
    if (pin.check(oldPIN,(short) 0 , (byte) 5) == false) {
        ISOException.throwIt(SW_VERIFICATION_FAILED);
    }

    // Update the PIN
    pin.update(newPIN, (short) 0, (byte) 5);
}

private void set_vacation(APDU apdu) {
	
	 if (!pin.isValidated()) {
	        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
	    }
		
	 byte[] buffer = apdu.getBuffer();

	 byte byteRead = (byte) (apdu.setIncomingAndReceive());

	 if ((buffer[ISO7816.OFFSET_LC] != 6) || (byteRead != 6)) {
	         ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	     }

	 // get  start_vacation : zz ll aa end_vacation: zz ll aa
	 byte zz1 = buffer[ISO7816.OFFSET_CDATA];
	 byte ll1 = buffer[ISO7816.OFFSET_CDATA+1];
	 byte aa1 = buffer[ISO7816.OFFSET_CDATA+2];
	 byte zz2 = buffer[ISO7816.OFFSET_CDATA+3];
	 byte ll2 = buffer[ISO7816.OFFSET_CDATA+4];
	 byte aa2 = buffer[ISO7816.OFFSET_CDATA+5];

	 boolean had=false;
	 if(start_vacation[1]==ll1 && end_vacation[1]==ll1)
		 if((end_vacation[0]-start_vacation[0])>10)
			 had=true;
    else //concediul a inceput in luna anterioara si s-a sfarsit in luna curenta
   	 if(end_vacation[1]==ll1)
   		 if(end_vacation[0]>10)
   			 had=true;
	 //verific daca are drept la concediu
	 if((cod_diag_cronic==0x00 && cod_spec_cronic==0x00 && had==false) //nu este pacient cronic, nu a avut m mult de 10 zile de concediu medical
			 ||(cod_diag_cronic!=0x00 && cod_spec_cronic!=0x00)) //este pacient cronic
	 {
		 start_vacation[0]=zz1;start_vacation[1]=ll1;start_vacation[2]=aa1;
		 end_vacation[0]=zz2;end_vacation[1]=ll2;end_vacation[2]=aa2;
	 }
	 else
		 ISOException.throwIt(SW_VACATION_DENIED); 
	 
}

private void get_data(APDU apdu) {
    // access authentication
    if (!pin.isValidated()) {
        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    }
    byte[] buffer = apdu.getBuffer();
    short offset = 0;
    
    // Retrieve and append the data to the response buffer
    buffer[offset++] = data_nasterii[0];
    buffer[offset++] = data_nasterii[1];
    buffer[offset++] = data_nasterii[2];
    buffer[offset++] = grupa_sangv;
    buffer[offset++] = rh;
    buffer[offset++] = cod_diag_cronic;
    buffer[offset++] = cod_spec_cronic;
    buffer[offset++] = cod_donator;
    if(consult1[0]!=0x00) {
    	for(short i=0; i<5; i++)
    		buffer[offset++]=consult1[i];
    	if(consult2[0]!=0x00) {
    		for(short i=0; i<5; i++)
        		buffer[offset++]=consult2[i];
    		if(consult3[0]!=0x00) 
        		for(short i=0; i<5; i++)
            		buffer[offset++]=consult3[i];
    	}
    		
    }
    buffer[offset++] = start_vacation[0];
    buffer[offset++] = start_vacation[1];
    buffer[offset++] = start_vacation[2];
    buffer[offset++] = end_vacation[0];
    buffer[offset++] = end_vacation[1];
    buffer[offset++] = end_vacation[2];
    // Send the response
    apdu.setOutgoingAndSend((short) 0, offset);

	
}
private void set_data(APDU apdu) {
	
    if (!pin.isValidated()) {
        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    }
	
	 byte[] buffer = apdu.getBuffer();

     byte byteRead = (byte) (apdu.setIncomingAndReceive());

     if ((buffer[ISO7816.OFFSET_LC] != 2) || (byteRead != 2)) {
         ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
     }

     // get option and code
     byte option = buffer[ISO7816.OFFSET_CDATA];
     byte new_code = buffer[ISO7816.OFFSET_CDATA+1];

     //verific optiunea primita
     // 0 - cod diagnostic cronic, 1 - cod specialitate cronica, 2 - cod donator
     switch (option) {
     case 0x00:
    	 cod_diag_cronic = new_code;
         return;       
     case 0x01:
    	 cod_spec_cronic = new_code;
         return;
     case 0x02:
    	 if(new_code!=0 && new_code!=1) // code donator(0 sau 1)
    		 ISOException.throwIt(SW_INVALID_DATA);
    	 cod_donator = new_code;
         return;   
 
     default:
         ISOException.throwIt(SW_INVALID_DATA);
 }
	   	
}

private void set_consult(APDU apdu) {
	
	 if (!pin.isValidated()) {
	        ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
	    }
		
	 byte[] buffer = apdu.getBuffer();

	 byte numBytes = (buffer[ISO7816.OFFSET_LC]);

	 byte byteRead = (byte) (apdu.setIncomingAndReceive());

	 if ((numBytes != 5) || (byteRead != 5)) {
	         ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	     }

	 // get cod_diag, cod_spec, data_diag: zz ll aa
	 byte diag = buffer[ISO7816.OFFSET_CDATA];
	 byte spec = buffer[ISO7816.OFFSET_CDATA+1];
	 byte zz = buffer[ISO7816.OFFSET_CDATA+2];
	 byte ll = buffer[ISO7816.OFFSET_CDATA+3];
	 byte aa = buffer[ISO7816.OFFSET_CDATA+4];
	 
	 boolean had=false;
	 //verific daca a mai avut consult la acea specialitate in luna data
	 if((consult1[3]==ll && consult1[1] == spec) 
			|| (consult2[3]==ll && consult2[1] == spec) || (consult3[3]==ll && consult3[1] == spec) )
	             had=true;
	 
    // verific daca pacientul are dreptul la consultatie
	if((cod_spec_cronic == spec) || ((cod_spec_cronic==0x00)&& (cod_diag_cronic==0x00) && had==false))
	{   byte[] non_init = {0x00,0x00,0x00,0x00,0x00};
		short nr_consults=0;
        if(Util.arrayCompare(consult1, (short)0,non_init, (short)0, (short)consult1.length) != 0) 
        	nr_consults++;
        if(Util.arrayCompare(consult2, (short)0,non_init, (short)0, (short)consult2.length) != 0) 
        	nr_consults++;
        if(Util.arrayCompare(consult3, (short)0,non_init, (short)0, (short)consult3.length) != 0) 
        	nr_consults++;
        switch (nr_consults) {
        case 0:
	         consult1[0]=diag;
	   		 consult1[1]=spec;
	   	     consult1[2]=zz;
	   	     consult1[3]=ll;
	   	     consult1[4]=aa;
             return;       
        case 1:
             consult2[0]=diag;
      		 consult2[1]=spec;
      	     consult2[2]=zz;
      	     consult2[3]=ll;
      	     consult2[4]=aa;
             return;
        case 2:
             consult3[0]=diag;
      		 consult3[1]=spec;
      	     consult3[2]=zz;
      	     consult3[3]=ll;
      	     consult3[4]=aa;
             return;    
        default:
        	Util.arrayCopyNonAtomic(consult2, (short) 0, consult1, (short) 0, (short) 5);
        	Util.arrayCopyNonAtomic(consult3, (short) 0, consult2, (short) 0, (short) 5);
        	consult3[0]=diag;
     		consult3[1]=spec;
     	    consult3[2]=zz;
     	    consult3[3]=ll;
     	    consult3[4]=aa;
            
	  }
    }
	else
		ISOException.throwIt(SW_CONSULT_DENIED);
		
  }

}


