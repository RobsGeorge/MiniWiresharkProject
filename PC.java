/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package networksproject.vipersteam;

import java.util.Date;

/**
 *
 * @author Robs
 */

public class PC {
    
    //Date d;
    private final int id;
    private final String source;
    private final String dest;
    private final int length;
    private final int headerLength;
    private final String Protocol;
    private final String info;
    
    public PC(int id, String source, String dest, int length, int headerLength, String Protocol, String info)
    {
        //this.d = d;
        this.id = id;
        this.source = source;
        this.dest = dest;
        this.length = length;
        this.headerLength = headerLength;
        this.Protocol = Protocol;
        this.info = info;
    }
    
    /*public Date getDate()
    {
        return d;
    }*/
    
    public int returnid()
    {
        return id;
    }
    
    public String getSource()
    {
        return source;
    }
    
    public String getDest()
    {
        return dest;
    }
    
    public int getLength()
    {
        return length;
    }
    
    public int getHeaderLength()
    {
        return headerLength;
    }
    
    public String getProtocol()
    {
        return Protocol;
    }
    
    public String getInfo()
    {
        return info;
    }
}

