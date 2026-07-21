function report(message) {
  print FILENAME ": " message > "/dev/stderr"
  failures++
}

function finish_job() {
  if (current_job == "") {
    return
  }
  if (timeout_count == 0) {
    report("job " current_job " is missing timeout-minutes")
  } else if (timeout_count > 1) {
    report("job " current_job " declares timeout-minutes more than once")
  }
  current_job = ""
  timeout_count = 0
}

BEGIN {
  in_jobs = 0
  job_count = 0
  failures = 0
}

{
  line = $0
  sub(/\r$/, "", line)

  if (!in_jobs) {
    if (line ~ /^(jobs|"jobs"|'jobs'):[[:space:]]*(#.*)?$/) {
      in_jobs = 1
    }
    next
  }

  if (line ~ /^[^[:space:]#]/) {
    finish_job()
    in_jobs = 0
    next
  }

  if (line ~ /^[[:space:]]*#/) {
    next
  }

  if (line ~ /^  [^[:space:]]/) {
    finish_job()
    if (line !~ /^  ([A-Za-z0-9_-]+|"[^"]+"|'[^']+'):[[:space:]]*(#.*)?$/) {
      report("unsupported job declaration: " line)
      next
    }
    current_job = line
    sub(/^  /, "", current_job)
    sub(/:[[:space:]]*(#.*)?$/, "", current_job)
    if (current_job ~ /^".*"$/ || current_job ~ /^'.*'$/) {
      current_job = substr(current_job, 2, length(current_job) - 2)
    }
    job_count++
    timeout_count = 0
    next
  }

  if (current_job != "" && line ~ /^    (timeout-minutes|"timeout-minutes"|'timeout-minutes')[[:space:]]*:/) {
    timeout_count++
    value = line
    sub(/^    (timeout-minutes|"timeout-minutes"|'timeout-minutes')[[:space:]]*:[[:space:]]*/, "", value)
    sub(/[[:space:]]*(#.*)?$/, "", value)
    if (value !~ /^[0-9]+$/ || value + 0 < 1 || value + 0 > 15) {
      report("job " current_job " must use a literal timeout-minutes from 1 through 15; found " value)
    }
  }
}

END {
  if (in_jobs) {
    finish_job()
  }
  if (job_count == 0) {
    report("contains no recognized jobs")
  }
  exit failures == 0 ? 0 : 1
}
