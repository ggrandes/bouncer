#!/bin/bash
BOUNCER_HOME=${BOUNCER_HOME:-/opt/bouncer}
BOUNCER_CONF=${BOUNCER_CONF:-bouncer.conf}
BOUNCER_MEM_MB=${BOUNCER_MEM_MB:-64}
BOUNCER_OPTS_DEF="-verbose:gc -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCTimeStamps -showversion -XX:+PrintCommandLineFlags -XX:-PrintFlagsFinal"
BOUNCER_OPTS="${BOUNCER_OPTS:-${BOUNCER_OPTS_DEF}}"
BOUNCER_CLASSPATH=$(echo $BOUNCER_HOME/lib/*.jar | tr ' ' ':')
#
do_reload () {
  touch ${BOUNCER_HOME}/conf/${BOUNCER_CONF}
}
do_keygen () {
  # org.javastack.bouncer.KeyGenerator <bits> <days> <CommonName> <filename-without-extension>
  local bits="${1}" days="${2}" cn="${3}" filebase="${4}"
  if [ "$filebase" = "" ]; then
    echo "$0 keygen <bits> <days> <CommonName> <filename-without-extension>"
    echo "Sample:"
    echo "$0 keygen 2048 365 host1.acme.com host1"
    exit 1;
  fi
  cd "${BOUNCER_HOME}/keys/"
  java \
    -cp "${BOUNCER_CLASSPATH}" \
    org.javastack.bouncer.KeyGenerator $bits $days $cn $filebase
  #chmod go-rwx "${filebase}.key"
  ls -al "${BOUNCER_HOME}/keys/${filebase}."*
}
do_run () {
  cd ${BOUNCER_HOME}
  java -Dprogram.name=bouncer ${BOUNCER_OPTS} -Xmx${BOUNCER_MEM_MB}m \
    -cp "${BOUNCER_HOME}/conf/:${BOUNCER_HOME}/keys/:${BOUNCER_CLASSPATH}" \
    org.javastack.bouncer.Bouncer ${BOUNCER_CONF}
}
do_start () {
  cd ${BOUNCER_HOME}
  echo "$(date --iso-8601=seconds) Starting" >> ${BOUNCER_HOME}/log/bouncer.bootstrap
  nohup java -Dprogram.name=bouncer ${BOUNCER_OPTS} -Xmx${BOUNCER_MEM_MB}m \
    -cp "${BOUNCER_HOME}/conf/:${BOUNCER_HOME}/keys/:${BOUNCER_CLASSPATH}" \
    -Dlog.stdOutFile=${BOUNCER_HOME}/log/bouncer.out \
    -Dlog.stdErrFile=${BOUNCER_HOME}/log/bouncer.err \
    org.javastack.bouncer.Bouncer ${BOUNCER_CONF} 1>>${BOUNCER_HOME}/log/bouncer.bootstrap 2>&1 &
  PID="$!"
  echo "Bouncer: STARTED [${PID}]"
}
do_stop () {
  PID="$(ps axwww | grep "program.name=bouncer" | grep -v grep | while read _pid _r; do echo ${_pid}; done)"
  if [ "${PID}" = "" ]; then
    echo "Bouncer: NOT RUNNING"
  else
    echo "$(date --iso-8601=seconds) Killing: ${PID}" >> ${BOUNCER_HOME}/log/bouncer.bootstrap
    echo -n "Bouncer: KILLING [${PID}]"
    kill -TERM ${PID}
    echo -n "["
    while [ -f "/proc/${PID}/status" ]; do
      echo -n "."
      sleep 1
    done
    echo "]"
  fi
}
do_status () {
  PID="$(ps axwww | grep "program.name=bouncer" | grep -v grep | while read _pid _r; do echo ${_pid}; done)"
  if [ "${PID}" = "" ]; then
    echo "Bouncer: NOT RUNNING"
  else
    echo "Bouncer: RUNNING [${PID}]"
  fi
}
case "$1" in
  run)
    do_stop
    trap do_stop SIGINT SIGTERM
    do_run
  ;;
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
  keygen)
    do_keygen $2 $3 $4 $5
  ;;
  *)
    echo "$0 <run|start|stop|restart|reload|status|keygen>"
  ;;
esac
