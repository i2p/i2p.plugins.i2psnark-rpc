package org.klomp.snark.rpc;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletException;

import net.i2p.I2PAppContext;
import net.i2p.app.ClientAppManager;

import org.klomp.snark.SnarkManager;

/**
 * The servlet.
 */
public class RPCServlet extends HttpServlet {
 
    private static final long serialVersionUID = 99999999L;
    
    private final I2PAppContext _context = I2PAppContext.getGlobalContext();

    private SnarkManager _manager;
    private XMWebUIPlugin _plugin;

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        XMWebUIPlugin plugin;
        synchronized(this) {
            ClientAppManager cmgr = _context.clientAppManager();
            if (cmgr == null) {
                resp.setContentType( "application/json; charset=UTF-8" );
                resp.sendError(403);
                _plugin = null;
                return;
            }
            SnarkManager smgr = (SnarkManager) cmgr.getRegisteredApp("i2psnark");
            if (smgr == null) {
                resp.setContentType( "application/json; charset=UTF-8" );
                resp.sendError(403);
                _plugin = null;
                return;
            }
            if (!smgr.equals(_manager)) {
                _manager = smgr;
                _plugin = new XMWebUIPlugin(_context, _manager);
            }
            plugin = _plugin;
        }
        boolean ok =  plugin.generateSupport(req, resp);
        if (!ok) {
            resp.setContentType( "application/json; charset=UTF-8" );
            resp.sendError(403);
        }
    }
    
    @Override
    public void destroy() {
        synchronized(this) {
            _manager = null;
            _plugin = null;
        }
        super.destroy();
    }
}
