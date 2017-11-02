/*
 * MIT License
 *
 * Copyright (c) 2017 Nick Taylor
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.HashMap;

/**
 * Main class
 */
public class BurpExtender implements IBurpExtender, IHttpListener {

    static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private MainPanel panel;
    private HashMap<URL, Long> reqResMap = new HashMap<>();
    private boolean isRunning = false;
    private int toolFilter = 0;

    //private PrintWriter stdout;

    /**
     * Called when plugin is loaded
     *
     * @param callbacks <code>IBurpExtenderCallbacks</code> object.
     */
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        //stdout = new PrintWriter(callbacks.getStdout(), true);
        // keep a reference to our callbacks object
        BurpExtender.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        // set our extension name
        callbacks.setExtensionName("Request Timer");
        panel = new MainPanel(this);
        // add the custom tab to Burp's UI
        callbacks.addSuiteTab(panel);
        // register ourselves as a listener
        callbacks.registerHttpListener(this);
    }

    /**
     * Set the running state
     *
     * @param running true or false
     */
    void setRunning(boolean running) {

        this.isRunning = running;
    }

    /**
     * Sets the source tool
     *
     * @param toolFilter int representing the tool
     */
    void setToolFilter(int toolFilter) {

        this.toolFilter = toolFilter;
    }

    /**
     * Process the HTTP message
     *
     * @param toolFlag  originating tool
     * @param messageIsRequest true if request, false if response
     * @param messageInfo <code>IHttpRequestResponse</code> object
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        if (isRunning) {
            if (toolFilter == 0 || toolFilter == toolFlag) {
                URL url = helpers.analyzeRequest(messageInfo).getUrl();
                if (messageIsRequest) {
                    reqResMap.put(url, System.currentTimeMillis());
                }
                else {
                    if (reqResMap.containsKey(url)) {
                        long time = System.currentTimeMillis() - reqResMap.get(url);
                        //stdout.println(helpers.analyzeRequest(messageInfo).getUrl() + ": " + time + "ms");
                        reqResMap.remove(url);
                        // create a new log entry with the message details
                        synchronized (panel.getLogTableModel().getLogArray()) {
                            int row = panel.getLogTableModel().getLogArray().size();
                            // Log all requests - the default
                            if (panel.getURLFilterText().isEmpty() && !panel.isScopeSelected()) {
                                addLog(messageInfo, toolFlag, time, row);
                            }
                            // Log filter URL requests
                            else if (!panel.isScopeSelected() && !panel.getURLFilterText().isEmpty() &&
                                    helpers.analyzeRequest(messageInfo).getUrl().toExternalForm().contains(panel.getURLFilterText())) {
                                addLog(messageInfo, toolFlag, time, row);
                            }
                            // Log in-scope requests
                            else if (panel.isScopeSelected() && panel.getURLFilterText().isEmpty() &&
                                    callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl())) {
                                addLog(messageInfo, toolFlag, time, row);
                            }
                            // Log in-scope requests and filter
                            else if (panel.isScopeSelected() && !panel.getURLFilterText().isEmpty() &&
                                    callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl()) &&
                                    helpers.analyzeRequest(messageInfo).getUrl().toExternalForm().contains(panel.getURLFilterText())) {
                                addLog(messageInfo, toolFlag, time, row);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Helper to add a log entry
     *
     * @param messageInfo <code>IHttpRequestResponse</code> object
     * @param toolFlag tool
     * @param time time taken in ms
     * @param row row to insert at
     */
    private void addLog(IHttpRequestResponse messageInfo, int toolFlag, long time, int row) {

        panel.getLogTableModel().getLogArray().add(new Log(LocalDateTime.now(),
                                                           callbacks.getToolName(toolFlag),
                                                           callbacks.saveBuffersToTempFiles(messageInfo),
                                                           helpers.analyzeRequest(messageInfo).getUrl(),
                                                           helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode(),
                                                           helpers.analyzeResponse(messageInfo.getResponse()).getStatedMimeType(),
                                                           time));
        panel.getLogTableModel().fireTableRowsInserted(row, row);
    }

    /**
     * Get the request map
     *
     * @return the request map
     */
    HashMap<URL, Long> getReqResMap() {

        return reqResMap;
    }
}

