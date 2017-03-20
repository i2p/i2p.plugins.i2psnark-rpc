package org.klomp.snark.rpc;

public class TextualException
    extends RuntimeException
{

    /**
     * 
     */
    private static final long serialVersionUID = -3302508436945014676L;

    public TextualException() {
    }

    public TextualException(String arg0) {
        super(arg0);

    }

    public TextualException(Throwable arg0) {
        super(arg0);

    }

    public TextualException(String arg0, Throwable arg1) {
        super(arg0, arg1);

    }

}
