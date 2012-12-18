#!/bin/bash
BOUNCER_HOME=/opt/bouncer
JAVA_HOME=/opt/java/java16
#
do_reload () {
  touch $BOUNCER_HOME/conf/bouncer.conf
}
do_start () {
  cd $BOUNCER_HOME
  nohup $JAVA_HOME/bin/java -Dprogram.name=bouncer -Xmx64m -cp $BOUNCER_HOME/conf/:$BOUNCER_HOME/lib/bouncer-1.5.1.jar -Dlog.stdOutFile=$BOUNCER_HOME/log/bouncer.out -Dlog.stdErrFile=$BOUNCER_HOME/log/bouncer.err net.bouncer.SimpleBouncer 1>$BOUNCER_HOME/log/bouncer.bootstrap 2>&1 &
  PID="$!"
  echo "Bouncer: STARTED [$PID]"
}
do_stop () {
  PID="$(ps axwww | grep "program.name=bouncer" | grep -v grep | while read _pid _r; do echo $_pid; done)"
  if [ "$PID" = "" ]; then
    echo "Bouncer: NOT RUNNING"
  else
    echo -n "Bouncer: KILLING [$PID]"
    kill -TERM $PID
    echo -n "["
    while [ -f "/proc/$PID/status" ]; do
      echo -n "."
      sleep 1
    done
    echo "]"
  fi
}
do_status () {
  PID="$(ps axwww | grep "program.name=bouncer" | grep -v grep | while read _pid _r; do echo $_pid; done)"
  if [ "$PID" = "" ]; then
    echo "Bouncer: NOT RUNNING"
  else
    echo "Bouncer: RUNNING [$PID]"
  fi
}
case "$1" in
  start)
    do_stop
    do_start
  ;;
  stop)
    do_stop
  ;;
  restart)
    do_stop
    do_start
  ;;
  reload)
    do_reload
  ;;
  status)
    do_status
  ;;
  *)
    echo "$0 <start|stop|restart|reload|status>"
  ;;
esac
